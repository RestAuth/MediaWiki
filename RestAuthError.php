<?php

class MWRestAuthError extends MWException {
	function __construct( Exception $previous  ) {
		$this->code = $previous->getCode();
		$this->previous = $previous;

		parent::__construct( $message, $code, $previous );
	}

	function getPageTitle() {
		$class = strtolower( get_class( $this->getPrevious() ) );
		return wfMsg( $class . '-header' );
	}

	function getHTML() {
		global $wgShowExceptionDetails;
		$class = strtolower( get_class( $this->getPrevious() ) );
		$box_content = wfMsg( $class . '-body' );
		$box = '<div class="errorbox" style="float: none;">' . $box_content . "</div>";

		if ( $wgShowExceptionDetails ) {
			$box .= '<b>Status code:</b> ' . 
				$this->previous->getCode() . 
				"<br /><b>Message from authentication server:</b> " . $this->previous->getMessage();
		}

		return $box . parent::getHTML();
	}

	// todo: html error message:
	// <div class="errorbox">
	// <strong>headline</strong>
	// ...
	// </div>
}
?>
