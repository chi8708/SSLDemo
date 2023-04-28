using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace EnDemo.Controllers
{
    public class HomeController : Controller
    {
        string privateKey = @"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMQvzCKea+Gfvby8
vkos9JFtx5M5KEGnzUVOjv/9vqKNr3DBkmMUcaaxsQo22pmOtWFQM1WBufHPSawp
GFB7MK4wP6y2Whh7e4ltzyP/vv6kwxRufH5RTXAeG9TAW5AuHEokS7RyC5Vkis8c
i3EhElQw6gzTpSc/0l2ZF9QbGzvHAgMBAAECgYAVb8eVbMwK7kJ0Mgd04W6jyWQK
QS+V5Pj3/rp/XEGNT4ABCRWuv9gfR8E5hX7jUoWdKX9Cc5dWxbieGCtw99T8sldl
cwcUfMZuBDIBG5Nsqgcyz0lRDpl5t9cEitXRKS+9ZVdODsQ9hOX8e73XhH7o2nrg
U4SQQ0Ix1U2t2WuD2QJBAPXb7VY6ehqt1yqsSrLe7rKIU5vNIJ03aTLYsuGKwFh5
jXJEUpaxoZnxGLgLfTXVCAWGg4qpGdmQEaPEuOlN9I0CQQDMR17EGFfZo4UNjB6P
vjL//3N66o3un8sHHswmKIE4zrk5kJLLgPrvsKZZ1b3aovStYe86S6x0OHZf8jhv
EB6jAkAphHEIvak+9ho+p4eZuxG97k2IItSeF+xY3MUgVyjyB9y97hGwRuDOOSt+
cNo9C/Nl03hFIxctaSnBaQf8xeBFAkEAqDpCVbVCa64ZPa3d4TyeXWou3NPa7N/V
YFjBgM8sk+7SZRClg0gF32yXojW+sxYt77dOPrDhJZj2C0+7n+MjhwJBAJqb2+sy
PjzgPI/5RNjGwOpFGUCWV70s2q/JKic5vb3M38HRkqwFKvrit9fvlcL9op/+PiAz
UiD2p1b6LG4947k=
-----END PRIVATE KEY-----
";
        public ActionResult Index() 
        {
            return View();
        }
        public JsonResult Test(string name)
        {
            var keyXml = RsaUtil.LoadPrivateKeyPKCS8(privateKey);
            var deName=RsaUtil.DecryptString(name,keyXml);
            return Json(new { name=deName });
        }
    }
}