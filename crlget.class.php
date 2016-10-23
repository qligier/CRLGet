<?php
namespace Kentin\WebSec;

use Exception, InvalidArgumentException, RuntimeException, UnexpectedValueException;
use ZipArchive;

/*
 * A library to fetch Chromium's CRLSet
 *
 * @version 0.1.0
 * @author  Quentin Ligier
 *
 * @see https://dev.chromium.org/Home/chromium-security/crlsets The official documentation
 * @see https://github.com/agl/crlset-tools CRLSets tools
 */
class CRLGet {

    /**
     * @var defaultParams   Default URL parameters {
     *     @var string  id      Application ID (required)
     *     @var mixed   v       ?
     *     @var mixed   uc      ?
     * }
     */
    const defaultParams = [
        'id' => 'hfnkpimlhhgieaddgfemjhofmfblmnib',
        'v'  => '',
        'uc' => '',
    ];

    /**
     * @var defaultURL  The URL of the CRLSet
     */
    const defaultURL = 'http://clients2.google.com/service/update2/crx';

    /**
     * @var updateKeys  The mandatory attribute of the update message
     */
    const updateKeys = ['status', 'codebase', 'fp', 'hash', 'hash_sha256', 'size', 'version'];

    /**
     * @var spkiHashLen The length of a spki
     */
    const spkiHashLen = 32;



    /**
     * @var array|null A CRLSetUpdate or null
     */
    protected $CRLSetUpdate = null;

    /**
     * @var array|null A CRLSet or null
     */
    protected $CRLSet = null;

    /**
     * @var string|null The fetched application ID or null
     */
    protected $appId = null;




    /**
     * Fetch the current CRLSet
     *
     * @param  array   $user_params
     */
    public function getCRLSet(array $user_params = []) {
        $this->fetchCRLSetUpdate($user_params);
        $this->processCRLSet();
    }

    /**
     * Returns the value of a property
     *
     * @param  string  $name  The value to get
     *
     * @return mixed   The value
     * @throws Exception if the CRLSetUpdate or CRLSet have not been fetched
     * @throws InvalidArgumentException if the supplied name isn't a valid property
     */
    public function __get(string $name) {
        if ('appId' === $name)
            return $this->appId;

        // Properties in CRLSet
        if (null !== $this->CRLSet) {
            if (in_array($name, array_keys($this->CRLSet)))
                return $this->CRLSet[$name];
        }

        // Properties in CRLSetUpdate
        if (in_array($name, self::updateKeys)) {
            if (null !== $this->CRLSetUpdate)
                return $this->CRLSetUpdate[$name];
        }

        throw new InvalidArgumentException('CRLGet: the '.$name.' property doesn\'t exist. Please use the CRLGet::getCRLSet() method before');
    }



    /**
     *
     */
    protected function buildURL(array $params): string {
        if (!isset($params['id']))
            throw new InvalidArgumentException('CRLGet: appId is missing from the params');
        $this->appId = $params['id'];
        return self::defaultURL . '?' . http_build_query(['x' => http_build_query($params)]);
    }

    /**
     *
     */
    protected function fetchURL(string $url): string {
        if ((int)ini_get('allow_url_fopen'))
            return file_get_contents($url);
        if (extension_loaded('curl')) {
            $curl = curl_init($url);
            curl_setopt_array($curl, [
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HEADER         => false,
                CURLOPT_NOBODY         => false,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 5,
            ]);
            $content = curl_exec($curl);
            curl_close($curl);
            return $content;
        }
        throw new RuntimeException('CRLGet: no method found to fetch remote URL');
    }

    /**
     *
     */
    protected function fetchCRLSetUpdate(array $user_params) {
        $url = $this->buildURL($user_params + self::defaultParams);
        try {
            $CRLSetInfo = $this->fetchURL($url);
        } catch (Exception $e)  {
            throw new RuntimeException('CRLGet was unable to download information about CRLSet ('.$url.')');
        }

        try {
            $CRLSetInfo = json_decode(json_encode(simplexml_load_string($CRLSetInfo)), true);
        } catch (Exception $e) {
            throw new UnexpectedValueException('CRLGet: the supplied file isn\'t a valid XML file');
        }

        if (!$CRLSetInfo['app']['@attributes']['appid'] || $this->appId !== $CRLSetInfo['app']['@attributes']['appid'])
            throw new RuntimeException('CRLGet: the app in incorrect');

        if (!$CRLSetInfo['app']['updatecheck'])
            throw new RuntimeException('CRLGet: no update found');

        $CRLSetUpdate = $CRLSetInfo['app']['updatecheck']['@attributes'];

        if (!$this->checkForKeys($CRLSetUpdate, self::updateKeys))
            throw new RuntimeException('CRLGet: the updatecheck is invalid');

        if ('ok' !== $CRLSetUpdate['status'])
            throw new RuntimeException('CRLGet: the updatecheck is not ok');

        $this->CRLSetUpdate = $CRLSetUpdate;
    }

    /**
     *
     */
    protected function processCRLSet() {
        if (null === $this->CRLSetUpdate)
            throw new Exception('CRLGet: Can\'t process the CRLSet without CRLSetUpdate');

        $crx = $this->fetchURL($this->CRLSetUpdate['codebase']);

        if (hash('sha256', $crx) !== $this->CRLSetUpdate['hash_sha256'])
            throw new RuntimeException('CRLGet: hashs don\'t match');

        if ('Cr24' !== $this->stringShift($crx, 4))
            throw new RuntimeException('CRLGet: data is not crx');


        $this->CRLSet = [];
        $this->CRLSet['version']         = $this->stringShiftUnpack($crx, 4, 'V');
        $this->CRLSet['publicKeyLength'] = $this->stringShiftUnpack($crx, 4, 'V');
        $this->CRLSet['signatureLength'] = $this->stringShiftUnpack($crx, 4, 'V');
        $this->CRLSet['publicKey']       = base64_encode($this->stringShift($crx, $this->CRLSet['publicKeyLength']));
        $this->CRLSet['signature']       = base64_encode($this->stringShift($crx, $this->CRLSet['signatureLength']));


        // Uncompress the CRX payload
        /*
            // Another way to do it, file creation required
            $tempFile = tempnam(sys_get_temp_dir(), 'CRX');
            file_put_contents($tempFile, $crx);
            $zip = new ZipArchive;
            $zip->open($tempFile);
            for ($i = 0; $i < $zip->numFiles; ++$i) {
                $filename = $zip->getNameIndex($i);
                if ('crl-set' === $filename)
                    $CRLSet = $zip->getFromIndex($i);
                //elseif ('manifest.json' === $filename)
                //    $manifest = $zip->getFromIndex($i);
            }
            $zip->close();
            unlink($tempFile);
        */
        // See http://stackoverflow.com/a/23113182 for the idea
        // https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html for the ZIP structure
        $offset = 0;
        while (1) {
            // Find Central directory file header
            $offsetFound = strpos($crx, hex2bin('504b0102'), $offset);
            if (false === $offsetFound)
                throw new RuntimeException('CRLGet: cannot parse ZIP file');

            // Unpack the header values
            $head = unpack('Vsig/vver/vvern/vflag/vmeth/vmodt/vmodd/Vcrc32/Vcsize/Vsize/vnamelen/vexlen/vcommlen/vdisks/vintattr/Vextattr/Vfileoffset', substr($crx, $offsetFound, 46));
            if ('crl-set' !== substr($crx, $offsetFound + 46, $head['namelen'])) {
                $offset = $offsetFound + 46;
                continue;
            }
            $compressedCRLSet = substr($crx, $head['fileoffset'] + 30 + $head['namelen'] + $head['exlen'], $head['csize']);
            if (8 === $head['meth'])
                $CRLSet = gzinflate($compressedCRLSet);
            elseif (0 === $head['meth'])
                $CRLSet = $compressedCRLSet;
            elseif (12 === $head['meth'])
                $CRLSet = bzdecompress($compressedCRLSet);
            else
                throw new RuntimeException('CRLGet: unable to decompress CRLSet');
            break;
        }
        unset($crx);

        // Process the header
        $headerLength = $this->stringShiftUnpack($CRLSet, 1, 'C') + ($this->stringShiftUnpack($CRLSet, 1, 'C') << 8);
        $header       = json_decode($this->stringShift($CRLSet, $headerLength), true);
        $this->CRLSet = $header + $this->CRLSet;

        // Extract certificates
        $certificates = [];
        while (strlen($CRLSet) > 0) {
            $spki = base64_encode($this->stringShift($CRLSet, self::spkiHashLen));
            $certificates[$spki] = [];

            $nbSerials =  $this->stringShiftUnpack($CRLSet, 1, 'C')
                       + ($this->stringShiftUnpack($CRLSet, 1, 'C') << 8)
                       + ($this->stringShiftUnpack($CRLSet, 1, 'C') << 16)
                       + ($this->stringShiftUnpack($CRLSet, 1, 'C') << 24);

            for ($i = 0; $i < $nbSerials; ++$i) {
                $serialLength = $this->stringShiftUnpack($CRLSet, 1, 'C');
                $certificates[$spki][] = base64_encode($this->stringShift($CRLSet, $serialLength));
            }
        }
        $this->CRLSet['certificates'] = $certificates;
    }

    /**
     * Verify the existance of a list of element in an array
     *
     * @param  array  $array   The array to check
     * @param  array  $keys    The list of elements to check
     *
     * @return bool   true if all elements are set and non-null, false otherwise
     */
    protected function checkForKeys(array $array, array $keys): bool {
        foreach ($keys AS $key) {
            if (!isset($array[$key]))
                return false;
        }
        return true;
    }

    /**
     * Shift a substring off the beginning of a string
     *
     * @param  string  $string   The input string
     * @param  int     $length   The length of the substring
     *
     * @return string  The shifted string
     * @throws InvalidArgumentException if the length is invalid
     */
    protected function stringShift(string &$string, int $length): string {
        if ($length < 1 || $length > strlen($string))
            throw new InvalidArgumentException('CRLGet: the supplied length is invalid');

        // Get the substring at the beginning of $string
        $value = substr($string, 0, $length);

        // Remove that part of $string
        $string = substr($string, $length);
        return $value;
    }

    /**
     * Shift a substring off the beginning of a string and unpack it
     * @uses   CRLSet::stringShift()
     * @see    http://php.net/manual/en/function.pack.php for the format codes
     *
     * @param  string  $string   The input string
     * @param  int     $length   The length of the substring
     * @param  string  $format   The format code
     *
     * @return string  The shifted string
     * @throws InvalidArgumentException if the length is invalid
     */
    protected function stringShiftUnpack(string &$string, int $length, string $format) {
        $result = unpack($format, $this->stringShift($string, $length));
        if (count($result) === 1)
            return $result[1];
        return $result;
    }

}
