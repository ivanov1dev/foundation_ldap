<?php

/**
 * Class FoundationLdap
 */
class FoundationLdap extends LdapServer {

  protected $system = 'registry';
  protected $platform = 'drupal';

  protected $permission_dn = 'cn=permissions,cn=pbac';
  protected $role_dn = 'cn=roles,cn=accounts';
  protected $privilege_dn = 'cn=privileges,cn=pbac';

  /**
   * @param string $name
   * @return string
   */
  public function prepareName($name) {
    return ucwords(sprintf('%s %s %s', $this->system, $this->platform, $name));
  }

  /**
   * @param string $name
   * @param string $dn
   * @param string $prefix
   * @return string
   */
  public function prepareDN($name, $dn, $prefix = 'cn') {
    return sprintf('%s=%s,%s,%s', $prefix, $name, $dn, end($this->basedn));
  }

  /**
   * @param string $permission_name
   * @return bool
   */
  public function createPermission($permission_name) {
    $permission_name = $this->prepareName($permission_name);
    $base_dn = end($this->basedn);
    $dn = $this->prepareDN($permission_name, $this->permission_dn);
    $entry = [
      'cn' => $permission_name,
      'objectclass' => [
        'groupofnames',
        'ipapermission',
        'ipapermissionv2',
        'top',
      ],
      'ipaPermBindRuleType' => 'permission',
      'ipaPermLocation' => $this->permission_dn . ',' . $base_dn,
      'ipaPermissionType' => [
        strtoupper('system'),
        strtoupper('v2'),
      ],
    ];

    if ($this->createLdapEntry($entry, $dn)) {
      return $dn;
    }

    $msg = t('Permission !entry not created.', ['!entry' => $dn]);
    watchdog('ldap_servers', $msg, [], WATCHDOG_ERROR);
    throw new RuntimeException($msg);
  }

  /**
   * @param string $permission_name
   * @param string $return
   * @param null $attributes
   * @return array|bool
   */
  public function permissionExists($permission_name, $return = 'boolean', $attributes = NULL) {
    $base_dn = $this->prepareDN($this->prepareName($permission_name), $this->permission_dn);
    return $this->dnExists($base_dn, $return, $attributes);
  }

  /**
   * @param string $role_name
   * @return bool|string
   */
  public function createRole($role_name) {
    $role_name = $this->prepareName($role_name);
    $dn = $this->prepareDN($role_name, $this->role_dn);

    $entry = [
      'cn' => $role_name,
      'objectclass' => [
        'groupofnames',
        'nestedgroup',
        'top',
      ],
    ];

    if ($this->createLdapEntry($entry, $dn)) {
      return $dn;
    }

    $msg = t('Role !entry not created.', ['!entry' => $dn]);
    watchdog('ldap_servers', $msg, [], WATCHDOG_ERROR);
    throw new RuntimeException($msg);
  }

  /**
   * @param string $privilege_name
   * @return bool|string
   */
  public function createPrivilege($privilege_name) {
    $privilege_name = $this->prepareName($privilege_name);
    $dn = $this->prepareDN($privilege_name, $this->privilege_dn);

    $entry = [
      'cn' => $privilege_name,
      'objectclass' => [
        'groupofnames',
        'nestedgroup',
        'top',
      ],
    ];

    if ($this->createLdapEntry($entry, $dn)) {
      return $dn;
    }

    $msg = t('Privilege !entry not created.', ['!entry' => $dn]);
    watchdog('ldap_servers', $msg, [], WATCHDOG_ERROR);
    throw new RuntimeException($msg);
  }

  /**
   * @param string $role_name
   * @param string $return
   * @param null $attributes
   * @return array|bool
   */
  public function roleExists($role_name, $return = 'boolean', $attributes = NULL) {
    $base_dn = $this->prepareDN($this->prepareName($role_name), $this->role_dn);
    return $this->dnExists($base_dn, $return, $attributes);
  }

  /**
   * @param string $privilege_name
   * @param string $return
   * @param null $attributes
   * @return array|bool
   */
  public function privilegeExists($privilege_name, $return = 'boolean', $attributes = NULL) {
    $base_dn = $this->prepareDN($this->prepareName($privilege_name), $this->privilege_dn);
    return $this->dnExists($base_dn, $return, $attributes);
  }

  /**
   * @param string $entry_dn
   * @param mixed $add_dn
   * @param string $link_type
   * @return bool
   */
  public function addEntry($entry_dn, $add_dn, $link_type = 'member') {
    $add = [
      $link_type => $add_dn,
    ];
    $this->connectAndBindIfNotAlready();
    $result = @ldap_mod_add($this->connection, $entry_dn, $add);
    if (!$result) {
      watchdog('ldap_servers', "Record !add not added in !entry.", ['!add' => $add_dn, '!entry' => $entry_dn], WATCHDOG_WARNING);
    }
    return $result;
  }

  /**
   * @param string $privilege_dn
   * @param string $permission_dn
   * @return bool
   */
  public function bindPermission($privilege_dn, $permission_dn) {
    return $this->addEntry($permission_dn, $privilege_dn);
  }

  /**
   * @param string $privilege
   * @param string $new_perm
   * @return bool|mixed
   */
  public function addPermission($privilege, $new_perm) {
    $result = FALSE;
    if ($permission = $this->permissionExists($new_perm, 'ldap_entry')) {
      // Добавляем к привилегии
      $this->bindPermission($privilege, $permission['dn']);
      $result = $permission['dn'];
    }
    else {
      // Создаем право
      if ($permission = $this->createPermission($new_perm)) {
        // Добавляем к привилегии
        $this->bindPermission($privilege, $permission);
        $result = $permission;
      }
    }
    return $result;
  }

  /**
   * @param string $role_dn
   * @param string $privilege_dn
   * @return bool
   */
  public function bindPrivilege($role_dn, $privilege_dn) {
    return $this->addEntry($privilege_dn, $role_dn);
  }

  /**
   * @param string $entry_dn
   * @param string $prefix
   * @return string
   */
  public function parseEntryName($entry_dn, $prefix = 'cn') {
    $temp = mb_strtolower(rtrim(reset(array_filter(explode("$prefix=", $entry_dn))), ','));
    return trim(substr($temp, strlen("$this->system $this->platform")));
  }

  /**
   * @param string $target
   * @param string $source
   * @return array
   */
  public function intersectEntries($target, $source) {
    $temp = [$target, $source];
    foreach ($temp as $i => &$entries) {
      if (preg_grep('/^cn/', $entries)) {
        foreach ($entries as $k => $entry) {
          $temp[$i][$k] = $this->parseEntryName($entry);
        }
      }
    }

    return array_intersect(...$temp);
  }

  /**
   * @param string $target
   * @param string $source
   * @return array
   */
  public function diffEntries($target, $source) {
    $temp = [$target, $source];
    foreach ($temp as $i => &$entries) {
      if (preg_grep('/^cn/', $entries)) {
        foreach ($entries as $k => $entry) {
          $temp[$i][$k] = $this->parseEntryName($entry);
        }
      }
    }

    return array_diff(...$temp);
  }

  /**
   * @param string $parent_dn
   * @param string $member_dn
   * @return bool
   */
  public function removeMember($parent_dn, $member_dn) {
    $result = FALSE;
    if ($parent = $this->dnExists($parent_dn, 'ldap_entry', [$this->groupMembershipsAttr])) {
      if (!empty($parent[$this->groupMembershipsAttr])) {
        $items = $parent[$this->groupMembershipsAttr];
        unset($items['count']);
        $pos = array_search($member_dn, $items);
        if ($pos !== FALSE) {
          unset($items[$pos]);

          $result = @ldap_mod_replace($this->connection, $parent_dn, [
            $this->groupMembershipsAttr => $items,
          ]);
        }
      }
    }

    return $result;
  }
}

