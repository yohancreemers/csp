# csp
A PHP class to construct Content Security Policy Level 2 headers

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
