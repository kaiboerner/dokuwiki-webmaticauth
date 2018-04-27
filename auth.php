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

	const WHERE = '
		enabled = 1
		AND kunde_id IS NULL
		AND (roles LIKE \'%"ROLE_INTERN"%\' OR roles LIKE \'%"ROLE_SUPER_ADMIN"%\')
		';


	/**
	* @var PDO
	*/
	private $db;


	/**
	* Constructor.
	*/
	public function __construct()
	{
		parent::__construct(); // for compatibility

		$this->success = false;

		$this->initDb();
		$this->initUsers();

		$this->cando['addUser'] = false; // can Users be created?
		$this->cando['delUser'] = false; // can Users be deleted?
		$this->cando['modLogin'] = false; // can login names be changed?
		$this->cando['modPass'] = false; // can passwords be changed?
		$this->cando['modName'] = true; // can real names be changed?
		$this->cando['modMail'] = false; // can emails be changed?
		$this->cando['modGroups'] = true; // can groups be changed?
		$this->cando['getUsers'] = true; // can a (filtered) list of users be retrieved?
		$this->cando['getUserCount'] = true; // can the number of users be retrieved?
		$this->cando['getGroups'] = true; // can a list of available groups be retrieved?
		$this->cando['external'] = false; // does the module do external auth checking?
		$this->cando['logout'] = true; // can the user logout again? (eg. not possible with HTTP auth)

		$this->success = true;
	}

	/**
	* @return array
	*/
	public function __sleep ()
	{
		$this->success = false;
		return array('canDo', 'success');
	}

	/**
	*
	*/
	public function __wakeup()
	{
		$this->initDb();
		$this->initUsers();
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
		$user = $this->db->quote($user);
		$password = $this->db->query("
			SELECT password
			FROM user
			INNER JOIN dokuwiki_user USING (user_id)
			WHERE username = $user
			LIMIT 1"
		)->fetchColumn();
		if ( empty($password) )
		{
			return false;
		}
		return password_verify($pass, $password);
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
	public function getUserData($user, $requireGroups=true)
	{
		$user = $this->db->quote($user);
		$stmt = $this->db->query("
			SELECT u.user_id, name, email AS mail
			FROM user AS u
			INNER JOIN dokuwiki_user USING (user_id)
			WHERE username = $user
			LIMIT 1"
		);
		$data = $stmt->fetch();
		if ( empty($data) )
		{
			return false;
		}
		$user_id = $data['user_id'];
		unset($data['user_id']);
		if ( $requireGroups )
		{
			global $conf;
			$data['grps'] = array(strtolower($conf['defaultgroup']));
			$stmt = $this->db->query("
				SELECT group_name
				FROM dokuwiki_group
				INNER JOIN dokuwiki_user_group USING (group_id)
				WHERE user_id = $user_id"
			);
			while ( $group = $stmt->fetchColumn() )
			{
				$data['grps'][] = $group;
			}
		}
		return $data;
	}

	/**
	* Log off the current user [ OPTIONAL ]
	*
	* Is run in addition to the ususal logoff method. Should
	* only be needed when trustExternal is implemented.
	*
	* @see     auth_logoff()
	* @author  Andreas Gohr <andi@splitbrain.org>
	*/
	public function logOff()
	{
		session_unset();
		session_destroy();
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
	public function modifyUser($user, $changes)
	{
		if ( is_array($changes) )
		{
			$user = $this->db->quote($user);
			$user_id = $this->db->query("
				SELECT user_id
				FROM user
				WHERE username = $user
				LIMIT 1"
			)->fetchColumn();
			if ( empty($user_id) )
			{
				return false;
			}
			array_walk_recursive($changes, 'trim');
			if ( !empty($changes['name']) )
			{
				$name = $this->db->quote($changes['name']);
				$this->db->exec ("
					UPDATE dokuwiki_user
					SET name = $name
					WHERE user_id = $user_id
					LIMIT 1"
				);
			}
			if ( !empty($changes['grps']) )
			{
				$changes['grps'] = array_map('strtolower', $changes['grps']);
				global $conf;
				$group = strtolower($conf['defaultgroup']);
				$changes['grps'] = array_diff($changes['grps'], array($group));
				$groups = array();
				$stmt = $this->db->query("
					SELECT group_name
					FROM dokuwiki_group
					INNER JOIN dokuwiki_user_group USING (group_id)
					WHERE user_id = $user_id"
				);
				while ( $group = $stmt->fetchColumn() )
				{
					$groups[] = $group;
				}
				$insert = array_map(array($this->db, 'quote'), array_diff($changes['grps'], $groups));
				$delete = array_map(array($this->db, 'quote'), array_diff($groups, $changes['grps']));
				foreach ( $insert as $group )
				{
					$this->db->exec("INSERT IGNORE INTO dokuwiki_group SET group_name = $group");
					$this->db->exec("
						INSERT INTO dokuwiki_user_group (user_id, group_id)
						SELECT $user_id, group_id
						FROM dokuwiki_group
						WHERE group_name = $group
						LIMIT 1"
					);
				}
				foreach ( $delete as $group )
				{
					$this->db->exec("
						DELETE u.*
						FROM dokuwiki_user_group AS u
						INNER JOIN dokuwiki_group USING (group_id)
						WHERE user_id = $user_id AND group_name = $group"
					);
				}
			}
		}
		return true;
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
		$stmt = $this->db->query($this->retrieveUsersSql($start, $limit, $filter));
		$result = array();
		while ( $row = $stmt->fetch() )
		{
			$row['grps'] = array_filter(array_map('trim', explode(',', $row['grps'])));
			$result[$row['user']] = $row;
		}
		return $result;
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
	public function getUserCount($filter = array())
	{
		$stmt = $this->db->query($this->retrieveUsersSql(0, 0, $filter));
		$result = $stmt->rowCount();
		$stmt->closeCursor();
		return $result;
	}

	/**
	* Define a group [implement only where required/possible]
	*
	* Set addGroup capability when implemented
	*
	* @param   string $group
	* @return  bool
	*/
	public function addGroup($group)
	{
		$group = trim($group);
		if ( empty($group) )
		{
			return false;
		}
		$group = $this->db->quote(strtolower($group));
		return $this->db->exec("INSERT IGNORE INTO dokuwiki_group SET group_name = $group");
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
	public function retrieveGroups($start = 0, $limit = 0)
	{
		$limit = $this->getLimit($start, $limit);
		global $conf;
		$group = $this->db->quote(strtolower($conf['defaultgroup']));
		$stmt = $this->db->query("
			SELECT group_name
			FROM dokuwiki_group
			UNION
			SELECT $group AS group_name
			ORDER BY group_name
			$strLimit"
		);
		$result = array();
		while ( $group = $stmt->fetchColumn() )
		{
			$result[] = $group;
		}
		return $result;
	}

	/**
	* Return case sensitivity of the backend
	*
	* When your backend is caseinsensitive (eg. you can login with USER and
	* user) then you need to overwrite this method and return false
	*
	* @return bool
	*/
	public function isCaseSensitive()
	{
		return false;
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
	public function useSessionCache($user)
	{
		return false;
	}

	// additional

	/**
	* Get limit clause for SQL
	*
	* @param   int   $start
	* @param   int   $limit
	* @return  string
	*/
	private function getLimit (int $start, int $limit) : string
	{
		if ( $limit > 0 )
		{
			return sprintf('LIMIT %d, %d', $start, $limit);
		}
		if ( $start > 0 )
		{
			msg("there cannot be an offset without a limit", -1);
		}
		return '';
	}

	/**
	* Get SQL for retrieveUsers and getUserCount
	*
	* @param   int   $start     index of first user to be returned
	* @param   int   $limit     max number of users to be returned, 0 for unlimited
	* @param   array $filter    array of field/pattern pairs, null for no filter
	* @return  string
	*/
	public function retrieveUsersSql(int $start = 0, int $limit = 0, array $filter = null) : string
	{
		$where = '';
		$having = '';

		if ( is_array($filter) )
		{
			foreach ( $filter as $i => $v )
			{
				switch ( $i )
				{
					case 'mail' : $i = 'email'; break;
					case 'user' : $i = 'username'; break;
				}
				switch ( $i )
				{
					case 'email' :
					case 'name' :
					case 'username' :
						$q = $this->db->quote("%$v%");
						$where = empty($where)
							? "WHERE $i LIKE $q"
							: " AND $i LIKE $q";
						break;
					case 'grps' :
						$q = $this->db->quote("%$v%");
						$having = empty($having)
							? "HAVING $i LIKE $q"
							: " AND $i LIKE $q";
						break;
				}
			}
		}

		$limit = $this->getLimit($start, $limit);

		global $conf;
		$group = $this->db->quote(strtolower($conf['defaultgroup']));
		return "
			SELECT username AS user, name, email AS mail, CONCAT($group, ',', IFNULL(GROUP_CONCAT(group_name), '')) AS grps
			FROM user AS u
			INNER JOIN dokuwiki_user AS du USING (user_id)
			LEFT OUTER JOIN dokuwiki_user_group USING (user_id)
			LEFT OUTER JOIN dokuwiki_group USING (group_id)
			$where
			GROUP BY u.user_id, du.user_id
			$having
			ORDER BY user
			$limit";
	}

	/**
	*
	*/
	private function initDb ()
	{
		$this->db = new PDO(
			$this->getConf('dsn'),
			$this->getConf('db_user'),
			conf_decodeString($this->getConf('db_pass'))
		);
		$this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$this->db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
	}

	/**
	*
	*/
	private function initTables ()
	{
		$stmt = $this->db->query('SHOW TABLES LIKE \'dokuwiki_user\'');
		if ( !empty($stmt->fetchAll()) )
		{
			return;
		}
		$this->db->exec("
			CREATE TABLE dokuwiki_user (
				user_id INT UNSIGNED NOT NULL PRIMARY KEY,
				name VARCHAR(127) NOT NULL DEFAULT '',
				FOREIGN KEY (user_id) REFERENCES user (user_id) ON UPDATE CASCADE ON DELETE CASCADE
			)"
		);
		$this->db->exec("
			INSERT INTO dokuwiki_user
			SELECT user_id, username
			FROM user
			WHERE ".self::WHERE
		);
		$this->db->exec("
			CREATE TABLE dokuwiki_group (
				group_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
				group_name VARCHAR(63) NOT NULL DEFAULT '',
				UNIQUE (group_name)
			)"
		);
		$this->db->exec("
			INSERT INTO dokuwiki_group (group_name) VALUES
			('admin')"
		);
		$this->db->exec("
			CREATE TABLE dokuwiki_user_group (
				user_id INT UNSIGNED NOT NULL,
				group_id INT UNSIGNED NOT NULL,
				FOREIGN KEY (user_id) REFERENCES dokuwiki_user (user_id) ON UPDATE CASCADE ON DELETE CASCADE,
				FOREIGN KEY (group_id) REFERENCES dokuwiki_group (group_id) ON UPDATE CASCADE ON DELETE CASCADE,
				PRIMARY KEY (user_id, group_id)
			)"
		);
		$this->db->exec("
			INSERT INTO dokuwiki_user_group
			SELECT user_id, 1
			FROM user
			WHERE ".self::WHERE." AND roles LIKE '%\"ROLE_SUPER_ADMIN\"%'"
		);
	}

	/**
	*
	*/
	private function initUsers ()
	{
		$this->initTables();
		global $conf;
		$group = $this->db->quote(strtolower($conf['defaultgroup']));
		$this->db->exec("DELETE FROM dokuwiki_group WHERE group_name = $group LIMIT 1");
		$this->db->exec("
			INSERT IGNORE INTO dokuwiki_user
			SELECT user_id, username
			FROM user
			WHERE ".self::WHERE
		);
		$this->db->exec("
			DELETE FROM dokuwiki_user
			WHERE user_id NOT IN (
				SELECT user_id
				FROM user
				WHERE ".self::WHERE."
			)"
		);
	}

}

// vim:ts=4:sw=4:et:
