<?php
/**
 * DokuWiki Plugin webmaticauth (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Kai Börner <kb@webmatic.de>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_webmaticauth extends DokuWiki_Auth_Plugin
{

	const WHERE = 'enabled = 1 AND kunde_id IS NULL AND (roles LIKE \'%"ROLE_INTERN"%\' OR roles LIKE \'%"ROLE_SUPER_ADMIN"%\')';


	/**
	* @var PDO
	*/
	private $db;

	/**
	* @var auth_plugin_authplain
	*/
	private $plain;


	/**
	* Constructor.
	*/
	public function __construct()
	{
		parent::__construct(); // for compatibility

		$this->db = new PDO(
			$this->getConf('dsn'),
			$this->getConf('db_user'),
			conf_decodeString($this->getConf('db_pass'))
		);

		if ( !class_exists('auth_plugin_authplain') )
		{
			require_once __DIR__.'/../authplain/auth.php';
		}
		$this->plain = new auth_plugin_authplain();

		$this->cando['addUser'] = false; // can Users be created?
		$this->cando['delUser'] = false; // can Users be deleted?
		$this->cando['modLogin'] = false; // can login names be changed?
		$this->cando['modPass'] = false; // can passwords be changed?
		$this->cando['modName'] = $this->plain->canDo('modName'); // can real names be changed?
		$this->cando['modMail'] = false; // can emails be changed?
		$this->cando['modGroups'] = $this->plain->canDo('modGroups'); // can groups be changed?
		$this->cando['getUsers'] = true; // can a (filtered) list of users be retrieved?
		$this->cando['getUserCount'] = true; // can the number of users be retrieved?
		$this->cando['getGroups'] = $this->plain->canDo('getGroups'); // can a list of available groups be retrieved?
		$this->cando['external'] = false; // does the module do external auth checking?
		$this->cando['logout'] = $this->plain->canDo('logout'); // can the user logout again? (eg. not possible with HTTP auth)

		$this->success = true;
	}

	/**
	* Check user+password
	*
	* May be ommited if trustExternal is used.
	*
	* @param   string $user the user name
	* @param   string $pass the clear text password
	* @return  bool
	*/
	public function checkPass($user, $pass)
	{
		$stmt = $this->db->prepare(
			'SELECT password
			FROM user
			WHERE '.self::WHERE.' AND username = :user
			LIMIT 1'
		);
		$stmt->execute(array(':user' => $user));
		$data = $stmt->fetch(PDO::FETCH_ASSOC);
		if ( empty($data) || empty($data['password']) )
		{
			return false;
		}
		if ( password_verify($pass, $data['password']) )
		{
			$this->plain->modifyUser($user, array('pass' => $pass));
			return true;
		}
		return false;
	}

	/**
	* Return user info
	*
	* Returns info about the given user needs to contain
	* at least these fields:
	*
	* name string  full name of the user
	* mail string  email addres of the user
	* grps array   list of groups the user is in
	*
	* @param   string $user the user name
	* @return  array containing user data or false
	* @param   bool $requireGroups whether or not the returned data must include groups
	*/
	public function getUserData(string $user, bool $requireGroups=true)
	{
		$this->initUsers();
		return $this->plain->getUserData($user, $requireGroups);
	}

	/**
	* Modify user data [implement only where required/possible]
	*
	* Set the mod* capabilities according to the implemented features
	*
	* @param   string $user    nick of the user to be changed
	* @param   array  $changes array of field/value pairs to be changed (password will be clear text)
	* @return  bool
	*/
	public function modifyUser(string $user, array $changes = null) : bool
	{
		if ( empty($changes) || !is_array($changes) )
		{
			return false;
		}
		unset($changes['user'], $changes['pass']);
		return $this->plain->modifyUser($user, $changes);
	}

	/**
	* Bulk retrieval of user data [implement only where required/possible]
	*
	* Set getUsers capability when implemented
	*
	* @param   int   $start     index of first user to be returned
	* @param   int   $limit     max number of users to be returned, 0 for unlimited
	* @param   array $filter    array of field/pattern pairs, null for no filter
	* @return  array list of userinfo (refer getUserData for internal userinfo details)
	*/
	public function retrieveUsers($start = 0, $limit = 0, $filter = null)
	{
		$this->initUsers();
		return $this->plain->retrieveUsers($start, $limit, $filter);
	}

	/**
	* Return a count of the number of user which meet $filter criteria
	* [should be implemented whenever retrieveUsers is implemented]
	*
	* Set getUserCount capability when implemented
	*
	* @param  array $filter array of field/pattern pairs, empty array for no filter
	* @return int
	*/
	public function getUserCount(array $filter = array()) : int
	{
		$this->initUsers();
		return $this->plain->getUserCount($filter);
	}

	/**
	* Define a group [implement only where required/possible]
	*
	* Set addGroup capability when implemented
	*
	* @param   string $group
	* @return  bool
	*/
	public function addGroup(string $group) : bool
	{
		return $this->plain->addGroup($group);
	}

	/**
	* Retrieve groups [implement only where required/possible]
	*
	* Set getGroups capability when implemented
	*
	* @param   int $start
	* @param   int $limit
	* @return  array
	*/
	public function retrieveGroups(int $start = 0, int $limit = 0) : array
	{
		return $this->plain->retrieveGroups($start, $limit);
	}

	/**
	* Return case sensitivity of the backend
	*
	* When your backend is caseinsensitive (eg. you can login with USER and
	* user) then you need to overwrite this method and return false
	*
	* @return bool
	*/
	public function isCaseSensitive() : bool
	{
		return false;
	}

	/**
	* Sanitize a given groupname
	*
	* This function is applied to any groupname that is given to
	* the backend and should also be applied to any groupname within
	* the backend before returning it somewhere.
	*
	* This should be used to enforce groupname restrictions.
	*
	* Groupnames are to be passed without a leading '@' here.
	*
	* @param  string $group groupname
	* @return string the cleaned groupname
	*/
	public function cleanGroup(string $group) : string
	{
		return $this->plain->cleanGroup($group);
	}

	/**
	* Check Session Cache validity [implement only where required/possible]
	*
	* DokuWiki caches user info in the user's session for the timespan defined
	* in $conf['auth_security_timeout'].
	*
	* This makes sure slow authentication backends do not slow down DokuWiki.
	* This also means that changes to the user database will not be reflected
	* on currently logged in users.
	*
	* To accommodate for this, the user manager plugin will touch a reference
	* file whenever a change is submitted. This function compares the filetime
	* of this reference file with the time stored in the session.
	*
	* This reference file mechanism does not reflect changes done directly in
	* the backend's database through other means than the user manager plugin.
	*
	* Fast backends might want to return always false, to force rechecks on
	* each page load. Others might want to use their own checking here. If
	* unsure, do not override.
	*
	* @param  string $user - The username
	* @return bool
	*/
	public function useSessionCache(string $user) : bool
	{
		return false;
	}

	// additional

	/**
	*
	*/
	private function initUsers ()
	{
		$dbUsers = $this->db->query(
			'SELECT username, email
			FROM user
			WHERE '.self::WHERE
		)->fetchAll(PDO::FETCH_ASSOC);

		$plainUsers = $this->plain->retrieveUsers();

		foreach ( $dbUsers as $dbUser )
		{
			$found = false;
			foreach ( $plainUsers as $user => $info )
			{
				if ( strtolower($dbUser['username']) == strtolower($user) )
				{
					$found = true;
					$info['user'] = $dbUser['username'];
					$info['mail'] = $dbUser['email'];
					$this->plain->modifyUser($user, $info);
					break;
				}
			}
			if ( !$found )
			{
				$this->plain->createUser(
					$dbUser['username'],
					md5(microtime(false)),
					$dbUser['username'],
					$dbUser['email']
				);
			}
		}

		$delete = array();
		foreach ( $plainUsers as $user => $info )
		{
			$found = false;
			foreach ( $dbUsers as $dbUser )
			{
				if ( strtolower($dbUser['username']) == strtolower($user) )
				{
					$found = true;
					break;
				}
			}
			if ( !$found )
			{
				$delete[] = $user;
			}
		}
		$this->plain->deleteUsers($delete);
	}

}

// vim:ts=4:sw=4:et:
