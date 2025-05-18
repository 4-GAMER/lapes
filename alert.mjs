/* Copyright (C) 2023-2025 anonymous

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

// نظام تنبيهات للأخطاء البرمجية في متصفح PS4

// لا يمكننا فتح وحدة التحكم مباشرة في متصفح PS4، لذا نتأكد من ظهور الأخطاء كتنبيهات

addEventListener('unhandledrejection', event => {
    const reason = event.reason;
    alert(
        'خطأ غير معالج\n'
        + `${reason}\n`
        + `${reason.sourceURL}:${reason.line}:${reason.column}\n`
        + `${reason.stack}`
    );
});

addEventListener('error', event => {
    const reason = event.error;
    alert(
        'خطأ غير معالج\n'
        + `${reason}\n`
        + `${reason.sourceURL}:${reason.line}:${reason.column}\n`
        + `${reason.stack}`
    );
    return true;
});

// استيراد البرنامج ديناميكياً لالتقاط أخطاء الصياغة
import('./psfree.mjs');
