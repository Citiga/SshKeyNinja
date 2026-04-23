# Third-Party Notices

SshKeyNinja uses the following third-party software.

---

## EFF Large Wordlist
- **Source:** [https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt](https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt)
- **License:** [Creative Commons Attribution 3.0 (CC-BY 3.0)](https://creativecommons.org/licenses/by/3.0/)
- **Copyright:** © 2016 Electronic Frontier Foundation
- **Modifications:** None (used as-is)

---

## BouncyCastle.Cryptography

- **Version:** 2.6.2
- **License:** MIT
- **Project:** https://www.bouncycastle.org/csharp/
- **NuGet:** https://www.nuget.org/packages/BouncyCastle.Cryptography

```
Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc.
(https://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## SSH.NET (bcrypt_pbkdf implementation)

- **License:** ISC (originally from OpenBSD bcrypt by Damien Miller)
- **Project:** https://github.com/sshnet/SSH.NET
- **File:** `src/SshKeyNinja/BcryptPbkdf.cs`

The `BcryptPbkdf` class is a port of the bcrypt_pbkdf implementation from
SSH.NET, which was itself ported from the SSHJ Java library, originally based
on the OpenBSD bcrypt implementation.

```
Copyright (c) 2006 Damien Miller <djm@mindrot.org>
Copyright (c) 2010 Ryan D. Emerle

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```
