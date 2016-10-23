CRLGet
======

CRLGet is a PHP class for downloading the current [Chrome's CRLSet](https://dev.chromium.org/Home/chromium-security/crlsets).


## Requirement

* PHP 7
* `allow_url_fopen` activated or [cURL extension](http://php.net/manual/en/book.curl.php)
* No dependencies :)


## Usage

```php
<?php
$crlset = (new Kentin\WebSec\CRLGet)->getCRLSet();

$crlset->appID;
// string(32) "hfnkpimlhhgieaddgfemjhofmfblmnib"

$crlset->Sequence;
// int(3329)

$crlset->hash;
// string(28) "P5S5QD8r80I3I4wxURB8jN+e0xg="

$crlset->hash_sha256;
// string(64) "12bd1ea12c6e440e1153057c109ea1c5fcc59b76a01fcff56398c [...]"

$crlset->publicKey;
// string(392) "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhUZ+Rw4 [...]"

$crlset->signature;
// string(344) "NnmdEfQ25iL32UppOa4Fw0E8/XWqPpQqaw+DTr0PBBVQ+0VJsSiW [...]"

$crlset->NotAfter;
// int(1477554398)

$crlset->BlockedSPKIs;
/*
 * array(21) {
 *   [0]=>
 *   string(44) "GvVsmP8EPvkr6/9UzrtN1nolupVsgX8+bdPB5S61hME="
 *   [1]=>
 *   string(44) "PtvZrOY5uhotStBHGHEf2iPoWbL79dE31CQEXnkZ37k="
 *   [...]
 * }
 */

$crlset->certificates;
/*
 * array(59) {
 *   ["AZQG1XXPKFo8LYu/gTPgz65IOcmcwYFb3yREhyWefNI="]=>
 *   array(77) {
 *     [0]=>
 *     string(24) "ESEMDMvuxTqH8iOoA5AXzIKF"
 *     [1]=>
 *     string(24) "ESEQLpdp231Ni40UccD1XvXR"
 *     [...]
 *   }
 *   ["BRz5+pXkDpuD7a7aaWH2Fox4ecRmAXJHnN1RqwPOpis="]=>
 *   array(304) {
 *     [0]=>
 *     string(16) "Fdq3LAAAAAAyDA=="
 *     [1]=>
 *     string(8) "QDiPuQ=="
 *     [...]
 *   }
 *   [...]
 * }
 */

```


## Related

* [crlset-tools](https://github.com/agl/crlset-tools), _Tools for dealing with Chrome's CRLSets_ (Go)