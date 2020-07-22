<?php
use DBoho\OAuth2\Server\Storage\PDO\AuthCodeStorage;
use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ScopeEntity;

/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 16.03.16
 * Time: 19:33
 */
class AuthCodeStorageTest extends PDOTest
{
	/**
	 * @var AuthCodeStorage
	 */
	protected $authCode;
	/**
	 * @var AbstractServer
	 */
	protected $server;

	public function testGetFailed()
	{
		$authCode = $this->authCode->get('unknwon');

		$this->assertNull($authCode);
	}

	public function testGet()
	{
		$this->db->exec("INSERT INTO oauth_auth_codes
					VALUES ('10authCode', 1, DATETIME('NOW', '+1 DAY'), '/10Redirect');");

		$authCode = $this->authCode->get('10authCode');

		$this->assertNotNull($authCode);
		$this->assertEquals('10authCode', $authCode->getId());
		$this->assertEquals('/10Redirect', $authCode->getRedirectUri());
	}

	public function testCreate()
	{
		$this->authCode->create('20NewToken', 1024, 1, '/20Redirect');

		$stmt = $this->db->prepare("SELECT * FROM oauth_auth_codes WHERE auth_code = '20NewToken'");
		$stmt->execute();
		$this->assertSame([
				'auth_code' => '20NewToken',
				'session_id' => '1',
				'expire_time' => '1024',
				'client_redirect_uri' => '/20Redirect'
		], $stmt->fetch(PDO::FETCH_ASSOC));
	}

    public function testCreateFailedNoSession()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*session_id'");
        $this->authCode->create('20NewToken', 1024, null, '/20Redirect');
	}

    public function testCreateFailedNoExpired()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*expire_time'");
        $this->authCode->create('20NewToken', null, 1, '/20Redirect');
	}

    public function testCreateFailedNoCode()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*auth_code'");
        $this->authCode->create(null, 1024, 1, '/20Redirect');
	}

    public function testCreateFailedNoRedirect()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*client_redirect_uri'");
        $this->authCode->create('10AuthCode', 1024, 1, null);
	}

	public function testGetScopes()
	{
		$this->db->exec("INSERT INTO oauth_auth_codes
						VALUES ('10authCode', 1, DATETIME('NOW', '+1 DAY'), '/10Redirect');
						INSERT INTO oauth_scopes VALUES ('user.list', 'list users'), ('user.add', 'add user');
						INSERT INTO oauth_auth_code_scopes VALUES (10, '10authCode', 'user.list');");
		$authCode = (new AuthCodeEntity($this->server))->setId('10authCode');

		$scopes = $this->authCode->getScopes($authCode);

		$this->assertCount(1, $scopes);
		$this->assertEquals('user.list', $scopes[0]->getId());
		$this->assertEquals('list users', $scopes[0]->getDescription());
	}

	public function testGetScopesEmpty()
	{
		$authCode = (new AuthCodeEntity($this->server))->setId('10authCode');

		$scopes = $this->authCode->getScopes($authCode);

		$this->assertCount(0, $scopes);
	}

	public function testAssociateScope()
	{
		$authCode = (new AuthCodeEntity($this->server))->setId('10authCode');
        $scope = (new ScopeEntity($this->server))->hydrate(['id' => 'user.list', 'description' => 'list user']);

		$this->authCode->associateScope($authCode, $scope);

		$stmt = $this->db->prepare(
		    "SELECT auth_code, scope FROM oauth_auth_code_scopes WHERE auth_code = '10authCode'");
		$stmt->execute();
		$this->assertSame(['10authCode', 'user.list'], $stmt->fetch(PDO::FETCH_NUM));
	}

	public function testDelete()
	{
		$this->db->exec("INSERT INTO oauth_auth_codes
					VALUES ('10authCode', 1, DATETIME('NOW', '+1 DAY'), '/10Redirect');");
		$authCode = (new AuthCodeEntity($this->server))->setId('10authCode');


		$this->authCode->delete($authCode);

		$stmt = $this->db->prepare("SELECT * FROM oauth_auth_codes WHERE auth_code = '10authCode'");
		$stmt->execute();
		$this->assertSame([], $stmt->fetchAll(PDO::FETCH_ASSOC));
	}


	protected function setUp()
	{
		parent::setUp();
		$this->authCode = new AuthCodeStorage($this->db);
		$this->server = $this->createMock(AbstractServer::class);

		$this->authCode->setServer($this->server);
	}

}
