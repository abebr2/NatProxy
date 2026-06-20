# NatProxy — SOCKS5 Proxy برای کنسول 🎮

اپ اندروید برای اجرای پروکسی SOCKS5 روی گوشی و اشتراک‌گذاری VPN با کنسول (Xbox / PS5).

---

## ساختار پروژه

```
NatProxy/
├── app/src/main/
│   ├── java/com/natproxy/app/
│   │   ├── MainActivity.kt         ← رابط کاربری
│   │   └── Socks5ProxyService.kt   ← سرور SOCKS5 (منطق اصلی)
│   ├── res/
│   │   ├── layout/activity_main.xml
│   │   └── values/colors.xml, strings.xml
│   └── AndroidManifest.xml
├── build.gradle
└── settings.gradle
```

---

## نحوه Build کردن

### پیش‌نیاز
- **Android Studio** (Hedgehog یا جدیدتر)
- **JDK 17**

### مراحل
1. Android Studio را باز کنید
2. روی **Open** کلیک کنید و پوشه `NatProxy` را انتخاب کنید
3. صبر کنید تا Gradle sync تمام شود
4. روی **▶ Run** کلیک کنید یا:
   - از منو: **Build → Build Bundle(s) / APK(s) → Build APK(s)**
   - فایل APK در `app/build/outputs/apk/debug/` ساخته می‌شود

---

## قابلیت‌ها

- ✅ سرور SOCKS5 کامل (TCP)
- ✅ شناسایی خودکار IP وای‌فای
- ✅ اجرا در پس‌زمینه (Foreground Service)
- ✅ نمایش لاگ زنده
- ✅ رابط کاربری فارسی
- ✅ نیازی به Termux یا root ندارد

---

## نحوه استفاده

1. اپ را نصب کنید
2. روی **شناسایی** بزنید تا IP گوشی شناسایی شود
3. روی **شروع پروکسی** بزنید
4. در کنسول: Settings → Network → Proxy → Manual
   - IP: همان IP نمایش داده شده
   - Port: 9898
