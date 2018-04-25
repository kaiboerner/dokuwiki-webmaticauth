<?php
/**
 * Options for the webmaticauth plugin
 *
 * @author Kai Börner <kb@webmatic.de>
 */


$meta['dsn'] = array('string');
$meta['db_user'] = array('string');
$meta['db_pass'] = array('string', '_code' => 'uuencode');
