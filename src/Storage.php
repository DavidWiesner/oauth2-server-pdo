<?php
/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 16.03.16
 * Time: 10:09
 */

namespace DBoho\OAuth2\Server\Storage\PDO;


use League\OAuth2\Server\Storage\AbstractStorage;
use PDO;
use PDOException;

class Storage extends AbstractStorage
{
	/**
	 * @var PDO
	 */
	protected $pdo;
	/**
	 * @var bool
	 */
	protected $supportsReturning;


	/**
	 * Storage constructor.
	 * @param PDO $pdo
	 */
	public function __construct(PDO $pdo)
	{
		$this->pdo = $pdo;
		$this->supportsReturning = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql';
	}

	/**
	 * prepare and execute sql statement on the pdo. Run PDO::fetchAll on select, describe or pragma statements
	 *
	 * @param string $sql This must be a valid SQL statement for the target database server.
	 * @param array $bind [optional]
	 *                     An array of values with as many elements as there are bound parameters in the SQL statement
	 *                     being executed
	 * @param bool $shouldThrow if throw PDOException if prepare or execute failed otherwise return false (default true )
	 * @param bool $returnStatement if true always return \PDOStatement
	 * @return array|false|int|\PDOStatement <ul>
	 *                     <li> associative array of results if sql statement is select, describe or pragma
	 *                     <li> the number of rows affected by a delete, insert, update or replace statement
	 *                     <li> the executed PDOStatement otherwise</ul>
	 *                     <li> false only if execution failed and the PDO::ERRMODE_EXCEPTION was unset</ul>
	 * @see PDO::execute
	 * @see PDO::prepare
	 */
	public function run($sql, $bind = array(), $shouldThrow = true, $returnStatement = false)
	{
		$sql = trim($sql);
		$statement = $this->pdo->prepare($sql);
		if ($statement !== false and ($statement->execute($bind) !== false)) {
			if ($returnStatement) {
				return $statement;
			} elseif (preg_match('/^(select|describe|pragma) /i', $sql)) {
				return $statement->fetchAll(PDO::FETCH_ASSOC);
			} elseif (preg_match('/^(delete|insert|update|replace) /i', $sql)) {
				return $statement->rowCount();
			} else {
				return $statement;
			}
		}
		if ($shouldThrow) {
			throw new PDOException($this->pdo->errorCode() . ' ' . ($statement === false ? 'prepare' : 'execute') . ' failed');
		}
		return false;
	}
}
