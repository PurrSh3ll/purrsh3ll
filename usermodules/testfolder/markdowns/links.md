# 🔗 Link Tests

Short test list for verifying how the Markdown viewer handles different links.

---

## ✅ Working Links

Links that should resolve correctly.

* [Google](https://google.com)
* [path-to-file](/etc/os-release)
* [path-to-folder](/home/kali)
* [path-rel-file](testdir1/testfile)
* [path-rel-dir](testdir1)
* [run sample command](action://run/command/echo%20Hello%20World%21)
* [try theme cyberpunk](action://change/theme/Cyberpunk)

---

## ❌ Not Existing / Broken Links

Links intentionally pointing to missing resources.

* [File-not-exist](file:///C:/test/notexist.file)
* [Rel-not-exist](docs/notexist)

---
