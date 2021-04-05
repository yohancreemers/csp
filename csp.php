<?php
/*
Copyright (c) 2020 Ylab, www.ylab.nl

A PHP class to construct Content Security Policy Level 2 headers as defined by the W3C

Inspired by https://github.com/martijnc/php-csp
Based on
	https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy

Class:
	\Y\inc\csp
Requires:
	PHP 7.0.0

Example for setting the Content Security Policy header:
<code>
	$oPolicy = new \Y\inc\csp();


	try{
		//set the default-src directive to 'none'
		$oPolicy->addSource(\Y\inc\csp::DIRECTIVE_DEFAULT_SRC, \Y\inc\csp::TOKEN_NONE);

		//set multiple directives to 'self'
		$oPolicy->addSource([\Y\inc\csp::DIRECTIVE_SCRIPT_SRC, \Y\inc\csp::DIRECTIVE_STYLE_SRC], 'self');

		//set the img-src directive to multiple sources
		$oPolicy->addSource(\Y\inc\csp::DIRECTIVE_IMG_SRC, 'self', 'data:', 'https://www.gravatar.com/avatar/');

		//use a auto generated nonce, and add the nonce to a script tag
		$oPolicy->addNonce(\Y\inc\csp::DIRECTIVE_SCRIPT_SRC)
						->addNonce(\Y\inc\csp::DIRECTIVE_STYLE_SRC);
		printf('<script nonce="%s" src="http://code.jquery.com/jquery-3.5.1.min.js"></script>', $oPolicy->nonce());

		//use a hash
		$sScript = "alert('Hello, world.');";
		$oPolicy->addHash(\Y\inc\csp::DIRECTIVE_SCRIPT_SRC, $sScript);

		$sHash = 'ZosEbRLbNQzLpnKIkEdrPv7lOy9C27hHQ+Xp8a4MxAQ=';
		$oPolicy->addHash(\Y\inc\csp::DIRECTIVE_SCRIPT_SRC, $sHash);

		//block all mixed content
		$oPolicy->blockAllMixedContent();

		//set theCSP headers
		$oPolicy->sendHeader();

		//tell the browser where to send the report with violations
		$oPolicy->reportUri('/api/cspreport');
		$oPolicy->sendReportOnlyHeader();

	}catch(\Y\inc\cspexceeption $e){
		echo($e->getMessage());
	}
</code>


Example for storing violation report:
<code>
	$sFilename = 'csp-report-' . date('Ymd-His') . '.json';
	\Y\inc\csp::report($sFilename);
</code>

NOTE ON the use of 'strict-dynamic' (CSP Level 3)
The 'strict-dynamic' token specifies that a script trusted for its nonce or a hash, is
allowed to load additional scripts (via non-"parser-inserted" script elements).
At the same time, any allow-list (https:...) and the source expressions 'self', 'unsafe-inline',
'unsafe-eval' are ignored by browsers supporting 'strict-dynamic'.
*/
namespace Y\inc;

class cspexceeption extends \Exception{}

class csp{
	//Document directives
	const DIRECTIVE_BASE_URI = 'base-uri';
	const DIRECTIVE_PLUGIN_TYPES = 'plugin-types';
	const DIRECTIVE_SANDBOX = 'sandbox';

	//Fetch directives
	const DIRECTIVE_CHILD_SRC = 'child-src';
	const DIRECTIVE_CONNECT_SRC = 'connect-src';
	const DIRECTIVE_DEFAULT_SRC = 'default-src';
	const DIRECTIVE_FONT_SRC = 'font-src';
	const DIRECTIVE_FRAME_SRC = 'frame-src';
	const DIRECTIVE_IMG_SRC = 'img-src';
	const DIRECTIVE_MEDIA_SRC = 'media-src';
	const DIRECTIVE_OBJECT_SRC = 'object-src';
	const DIRECTIVE_SCRIPT_SRC = 'script-src';
	const DIRECTIVE_STYLE_SRC = 'style-src';

	//Navigation directives
	const DIRECTIVE_FORM_ACTION = 'form-action';
	const DIRECTIVE_FRAME_ANCESTORS = 'frame-ancestors';

	//Supported SHA alogoritms
	const ALGO_SHA256 = 'sha256';
	const ALGO_SHA384 = 'sha384';
	const ALGO_SHA512 = 'sha512';

	const TOKEN_NONE = 'none';
	const TOKEN_STRICT_DYNAMIC = 'strict-dynamic';

	const HEADERNAME = 'Content-Security-Policy';
	const HEADERNAME_REPORTONLY = 'Content-Security-Policy-Report-Only';

	/**
	 * Tokens defined by CSP, must be enclosed in single quotes
	 *
	 * @var array
	 */
	protected $sourceTokens = ['self', 'unsafe-eval', 'unsafe-hashes', 'unsafe-inline', self::TOKEN_NONE, self::TOKEN_STRICT_DYNAMIC];

	/**
	 * Contains all the directives that have been defined and their respective values.
	 *
	 * @var array
	 */
	protected $directives = [];

	/**
	 * The 'number used once'.
	 *
	 * @var null
	 */
	protected $nonce;

	/**
	 * When set to a valid URI, the UA will send violation reports to this URI.
	 *
	 * @var null
	 */
	protected $reportUri;

	/**
	 * @var bool
	 */
	protected $blockAllMixedContent = false;

	/**
	 * @var bool
	 */
	protected $upgradeInsecureRequests = false;

	/**
	 * set the following properties:
	 * blockAllMixedContent
	 * upgradeInsecureRequests
	 * reportUri
	 *
	 * @return self
	 */
	public function __call($sMethod, $aArgs){
		switch($sMethod){
			case 'blockAllMixedContent':
			case 'upgradeInsecureRequests':
				//defaults to true
				$this->$sMethod = count($aArgs) == 0 ? true : (bool) $aArgs[0];
				break;
			case 'reportUri':
				$this->$sMethod = isset($aArgs[0]) && is_string($aArgs[0]) ? $aArgs[0] : null;;
				break;
			default:
				throw new cspexceeption($sMethod . ' is an invalid method.');
		}
		return $this;
	}

	/**
	 * constructor
	 * @param string $sBaseUri
	 * @param string $sDefaultSource
	 * @param boolean $bBlockLessSecure
	 *
	 * @return self
	 */
	public function __construct($sBaseUri='none', $sDefaultSource='self', $bBlockLessSecure=true){
		//Document directives
		$this->addSource(\Y\inc\csp::DIRECTIVE_BASE_URI, $sBaseUri);

		//default for Fetch directives
		$this->addSource(\Y\inc\csp::DIRECTIVE_DEFAULT_SRC, $sDefaultSource);

		//default for navigation directives, don't have a fallback on default-src
		$this->addSource(\Y\inc\csp::DIRECTIVE_FORM_ACTION, $sDefaultSource);
		$this->addSource(\Y\inc\csp::DIRECTIVE_FRAME_ANCESTORS, $sDefaultSource);

		//prevent loading any assets over HTTP when the page uses HTTPS.
		$this->blockAllMixedContent($bBlockLessSecure);
	}

	/**
	 * var dump
	 * @return array
	 */
	public function __debugInfo() {
		return $this->directives + [
			'blockAllMixedContent' => $this->blockAllMixedContent ? 'true' : 'false',
			'nonce' => $this->nonce,
			'policy' => $this->getHeaderValue(false),
			'report-uri' => $this->reportUri,
			'upgradeInsecureRequests' => $this->upgradeInsecureRequests ? 'true' : 'false',
		];
	}

	/*
	 * assemble and return the scp policy hader
	 * @return string
	*/
	public function __toString(){
		return $this->getHeader() ?? '';
	}

	/**
	 * @param string $sValue
	 * @return string|nulll
	 */
	private static function _base64algoritm(string $sValue){
		switch(strlen($sValue)){
			case 44: return self::ALGO_SHA256;
			case 64: return self::ALGO_SHA384;
			case 88: return self::ALGO_SHA512;
		}
	}

	/**
	 * @param string $sValue
	 * @return bool
	 */
	private static function _base64encoded(string $sValue){
		return preg_match('%^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$%', $sValue);
	}

	/**
	 * @param string $sPrefix
	 * @param string $sValue
	 * @return bool
	 */
	private static function _defined(string $sPrefix, string $sValue){
		$sConstant = sprintf('SELF::%s_%s', $sPrefix, strtoupper(str_replace('-', '_', $sValue)));
		return defined($sConstant);
	}

	/**
	 * @param string $value
	 * @return string
	 */
	private function _encodeDirectiveValue($value){
		if( in_array($value, $this->sourceTokens) ){
	 		//These are tokens defined by CSP and have specials meaning.
	 		//They have to be enclosed by quotes

			return sprintf("'%s'", $value);
		}

		return str_replace([';', ','], ['%3B', '%2C'], trim($value));
	}

	/**
	 * @param string $sDirective
	 * @return array
	 */
	private function _fallback(string $sDirective){
		switch($sDirective){
			case self::DIRECTIVE_CHILD_SRC:
			case self::DIRECTIVE_CONNECT_SRC:
			case self::DIRECTIVE_FONT_SRC:
			case self::DIRECTIVE_IMG_SRC:
			case self::DIRECTIVE_MEDIA_SRC:
			case self::DIRECTIVE_OBJECT_SRC:
			case self::DIRECTIVE_SCRIPT_SRC:
			case self::DIRECTIVE_STYLE_SRC:
				return $this->directives[self::DIRECTIVE_DEFAULT_SRC] ?? [];
			case self::DIRECTIVE_FRAME_SRC:
				return $this->_fallback(self::DIRECTIVE_CHILD_SRC);
		}
		return [];
	}

	/**
	 * @param array $aExpressions
	 * @return null|string
	 */
	private function _parseDirectiveValue(array $aExpressions){
		return implode(' ', array_map(function($sValue){
			return $this->_encodeDirectiveValue($sValue);
		}, $aExpressions));
	}

	/**
	 * Add a hash value
	 *
	 * @param mixed $directives - string or array of strings
	 * @param string $sAlgo
	 * @param string $sData
	 * @param bool $bStrictDynamic
	 * @return self
	 */
	public function addHash($directives, string $sData, string $sAlgo=null, bool $bStrictDynamic=false){
		$bHashed = in_array(strlen($sData), [44, 64, 88]) && $this->_base64encoded($sData);

		if( is_null($sAlgo) ){
			$sAlgo = $bHashed ? $this->_base64algoritm($sData) : self::ALGO_SHA256;
		}elseif( !self::allowedAlgo($sAlgo) ){
			throw new cspexceeption(
				'Invalid hash algoritm: ' . $sAlgo
			);
		}

		//hash en encode de data if needed
		$bHashed || $sData = base64_encode(hash($sAlgo, $sData, true));

		return $this->addSource($directives, sprintf("'%s-%s'", $sAlgo, $sData), $bStrictDynamic ? self::TOKEN_STRICT_DYNAMIC : null);
	}

	/**
	 * Add a nonce value
	 *
	 * @param mixed $directives - string or array of strings
	 * @param string $sNonce - generated if parameter is omitted
	 * @param bool $bStrictDynamic
	 * @return self
	 */
	public function addNonce(string $directives, string $sNonce=null, bool $bStrictDynamic=false){
		$sNonce = $this->nonce($sNonce);
		return $this->addSource($directives, sprintf("'nonce-%s'", $this->nonce), $bStrictDynamic ? self::TOKEN_STRICT_DYNAMIC : null);
	}

	/**
	 * Add a generic expression
	 * Note: will include the source of the former fallback if the directive isn't set yet
	 *       use ::set() if you don't want this smartness
	 *
	 * @param mixed $directives - string or array of strings
	 * @param string $sSource, [string $sSource]
	 * @throws \Y\inc\cspexceeption
	 * @return self
	 */
	public function addSource($directives, ...$aSources){
		$aSources = array_filter($aSources);
		foreach( (array) $directives as $sDirective  ){
			if( !self::allowedDirective($sDirective) ){
				throw new cspexceeption($sDirective . ' is an invalid directive.');
			}

			if( !isset($this->directives[$sDirective]) ){
				//first addition for this directive, start with the sources of it's former fallback
				$this->directives[$sDirective] = $this->_fallback($sDirective);
				ksort($this->directives);
			}

			foreach($aSources as $sSource){
				if( !in_array($sSource, $this->directives[$sDirective]) ){
					if( $sSource == self::TOKEN_NONE || reset($this->directives[$sDirective]) == self::TOKEN_NONE ){
						//'none' cannot be combined with other sources, remove the previous sources
						$this->directives[$sDirective] = [$sSource];
					}else{
						$this->directives[$sDirective][] = $sSource;
					}
				}
			}
		}
		return $this;
	}

	/**
	 * @param string $sAlgo
	 * @return bool
	 */
	public static function allowedAlgo(string $sAlgo){
		return self::_defined('ALGO', $sAlgo);
	}

	/**
	 * @param string $sDirective
	 * @return bool
	 */
	public static function allowedDirective(string $sDirective){
		return self::_defined('DIRECTIVE', $sDirective);
	}

	/**
	 * @param bool $bReportOnly
	 * @return string|null
	 */
	public function getHeader($bReportOnly=false){
		if( $value = $this->getHeaderValue($bReportOnly) ){
			$sName = $bReportOnly ? self::HEADERNAME_REPORTONLY : self::HEADERNAME;

			return sprintf('%s: %s', $sName, $value);
		}
	}

	/**
	 * Returns the value for the CSP header
	 *
	 * @param bool $bReportOnly
	 * @return string|null
	 */
	public function getHeaderValue($bReportOnly=false){
		$aDirectives = [];

		//remove 'unsafe-inline' from script-src and style-src when a nonce-source or hash-source is specified
		//- note: this ignores that 'unsafe-inline' can be used as fallback for browsers not supporting CSP Level 2 (which are all released before 2017)
		foreach([self::DIRECTIVE_SCRIPT_SRC, self::DIRECTIVE_STYLE_SRC] as $sDirective){
			if( isset($this->directives[$sDirective]) && preg_match('/\b(nonce|sha256|sha384|sha512)\b/', implode('|', $this->directives[$sDirective])) ){
				$this->removeSource($sDirective, 'unsafe-inline');
			}
		}

		foreach($this->directives as $sDirective => $aSources){
			//ignore an empty array of sources, browser would interprete this as 'none'.
			//- set 'none' explicitely if no sources are allowed
			if( !empty($aSources) ){
				$aDirectives[] = sprintf('%s %s', $sDirective, $this->_parseDirectiveValue($aSources));
			}
		}

		if( $this->upgradeInsecureRequests ){
			$aDirectives[] = 'upgrade-insecure-requests';
		}elseif( $this->blockAllMixedContent ){
			//The upgrade-insecure-requests directive is evaluated before block-all-mixed-content
			// and if it is set, the latter is effectively a no-op.
			//It is recommended to set either directive, but not both
			$aDirectives[] = 'block-all-mixed-content';
		}

		if( $bReportOnly && !empty($this->reportUri) ){
			//only add report-uri for Content-Security-Policy-Report-Only
			//         report-uri is deprecated for Content-Security-Policy
			$aDirectives[] = sprintf('report-uri %s', $this->reportUri);
		}

		if( count($aDirectives) > 0 ){
			//policies set
			return implode('; ', $aDirectives);
		}

	}

	/**
	 * set and/or get a nonce
	 *
	 * @param string $sNonce
	 * @return string
	 */
	public function nonce(string $sNonce=null){
		if( !empty($sNonce) ){
			//overwrite existing value
			$this->nonce = $sNonce;
		}elseif( empty($this->nonce) ){
			//not set yet, user random valuue
			$this->nonce = bin2hex(random_bytes(8));
		}

		return $this->nonce;
	}

	/**
	 * get the nonce attribute for use on a script tag
	 *
	 * @param string $sNonce
	 * @return string
	 */
	public function nonceAttribute(){
		if( !empty($this->nonce) ){
			//a nonce has been set
			return sprintf(' nonce="%s"', addcslashes($this->nonce, '"'));
		}

		return '';
	}

	/**
	 * Remove all source for the specified directive(s)
	 * Note: the fallback directive will come into effect again
	 *
	 * @param mixed $directives - string or array of strings
	 * @param boolean $bInitialize - false: unset directive - true: start with an empty array
	 * @throws \Y\inc\cspexceeption
	 * @return self
	 */
	public function removeAllSources($directives, $bInitialize=false){
		foreach( (array) $directives as $sDirective  ){
			if( !self::allowedDirective($sDirective) ){
				throw new cspexceeption($sDirective . ' is an invalid directive.');
			}
			if( $bInitialize ){
				$this->directives[$sDirective] = [];
			}else{
				unset($this->directives[$sDirective]);
			}
		}
		return $this;
	}

	/**
	 * Remove a source
	 *
	 * @param mixed $directives - string or array of strings
	 * @param string $sSource, [string $sSource]
	 * @throws \Y\inc\cspexceeption
	 * @return self
	 */
	public function removeSource($directives, ...$aSources){
		$aSources = array_filter($aSources);
		foreach( (array) $directives as $sDirective  ){
			if( !self::allowedDirective($sDirective) ){
				throw new cspexceeption($sDirective . ' is an invalid directive.');
			}

			if( !empty($this->directives[$sDirective]) ){
				foreach($aSources as $sSource){
					$iKey = array_search($sSource, $this->directives[$sDirective]);
					if( $iKey !== false ){
						unset($this->directives[$sDirective][$iKey]);
					}
				}
			}
		}
		return $this;
	}

	/**
	 * get the CSP violation report
	 *
	 * @param string $sFilename
	 * @param bool $bReturnJson
	 * @return object|string
	 */
	public static function report(string $sFilename=null, $bReturnJson=false){
		//get the raw POST data
		if( $sData = file_get_contents('php://input') ){
			if( $oData = json_decode($sData) ){
				//it's valid json
				if( $oReport = $oData->{'csp-report'} ?? false ){
					$oReport->{'document-uri'} = $oReport->{'document-uri'} ?? null;
					$oReport->{'blocked-uri'} = $oReport->{'blocked-uri'} ?? null;
					$oReport->{'source-file'} = $oReport->{'source-file'} ?? null;

					//Filter violations caused by browser extensions
					if( preg_match('%^moz-extension://%', $oReport->{'source-file'}) ){
						//violation caused by a firefox extension
						return;
					}
					if( preg_match('%^about$%', $oReport->{'document-uri'}) ){
						//violation caused by a chrome extension
						return;
					}

					$sPath = parse_url($oReport->{'document-uri'},  PHP_URL_PATH);
					if( preg_match('/\.pdf$/i', $sPath) && $oReport->{'blocked-uri'} == 'inline' ){
						//violation caused by pdf viewer
						return;
					}
					$oData->currenttime = date('H:i:s');
					$oData->useragent = $_SERVER['HTTP_USER_AGENT'] ?? 'none';

					//prettify the JSON-formatted data
					if( $sData = json_encode($oData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) ){

						//store the CSP violation report
						if( !empty($sFilename) ){
							file_put_contents($sFilename, $sData . NL, FILE_APPEND);
						}
					}

					return $bReturnJson ? $sData : $oData;
				}
			}
		}
	}

	/**
	 * @param bool $replace
	 * @return null
	 */
	public function sendHeader(bool $replace=true){
		if( $sContentSecuritPolicy = $this->getHeader() ){
			header($sContentSecuritPolicy, $replace);
		}
	}

	/**
	 * @param bool $replace
	 * @return null
	 */
	public function sendReportOnlyHeader(bool $replace=true){
		if( empty($this->reportUri) ){
			throw new cspexceeption('The report-uri has not been set. CSP cannot report violations of this policy.');
		}
		if( $sContentSecuritPolicy = $this->getHeader(true) ){
			header($sContentSecuritPolicy, $replace);
		}
	}

	/**
	 * Remove all existing sources, add one or more new sources
	 *
	 * @param mixed $directives - string or array of strings
	 * @param string $sSource, [string $sSource]
	 * @throws \Y\inc\cspexceeption
	 * @return self
	 */
	public function setSource($directives, ...$aSources){
		return $this->removeAllSources($directives, true)->addSource($directives, ...$aSources);
	}
}