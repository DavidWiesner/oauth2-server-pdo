<?php
use DBoho\OAuth2\Server\Storage\PDO\ClientStorage;
use DBoho\OAuth2\Server\Storage\PDO\SessionStorage;
use League\Event\Emitter;
use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;

class PDOMock extends PDO
{
	/** @noinspection PhpMissingParentConstructorInspection */

	/**
	 * PDOMock constructor.
	 */
	public function __construct()
	{
	}
}

/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 16.03.16
 * Time: 10:27
 */
class SessionStorageTest extends PDOTest
{
	/**
	 * @var SessionStorage
	 */
	protected $session;
	/**
	 * @var AbstractServer
	 */
	protected $server;
	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	protected $clientStorage;

	public function testGetByAccessTokenFail()
	{
		$accessToken = new AccessTokenEntity($this->server);
		$accessToken->setId('1234');

		$session = $this->session->getByAccessToken($accessToken);

		$this->assertNull($session);
	}

	public function testGetByAccessToken()
	{
		$this->db->exec("INSERT INTO oauth_sessions
						VALUES (19, 'user', '3', 'testclient', '/');
						INSERT INTO oauth_access_tokens
						VALUES ('1234', 19,  DATETIME('NOW', '+1 DAY'));");
		$accessToken = new AccessTokenEntity($this->server);
		$accessToken->setId('1234');
		$client = new ClientEntity($this->server);

		$session = $this->session->getByAccessToken($accessToken);

        /** @noinspection PhpParamsInspection */
        $this->clientStorage->expects($this->once())
            ->method('getBySession')->with($session)->willReturn([''=>$client]);
		$this->assertEquals(19, $session->getId());
		$this->assertEquals("user", $session->getOwnerType());
		$this->assertEquals(3, $session->getOwnerId());
		$this->assertSame([''=>$client], $session->getClient());
	}

	public function testGetByAuthCodeFail()
	{
		$authCode = (new AuthCodeEntity($this->server))->setId("1234");

		$session = $this->session->getByAuthCode($authCode);

		$this->assertNull($session);
	}

	public function testGetByAuthCode()
	{
		$this->db->exec("INSERT INTO oauth_sessions	VALUES (19, 'user', '3', 'testclient', '/');
						INSERT INTO oauth_auth_codes VALUES ('1234', 19,  DATETIME('NOW', '+1 DAY'), '/');");
		$authCode = (new AuthCodeEntity($this->server))->setId("1234");
		$client = new ClientEntity($this->server);

		$session = $this->session->getByAuthCode($authCode);

        /** @noinspection PhpParamsInspection */
        $this->clientStorage->expects($this->once())->method('getBySession')
            ->with($session)->willReturn([''=>$client]);
		$this->assertEquals(19, $session->getId());
		$this->assertEquals("user", $session->getOwnerType());
		$this->assertEquals(3, $session->getOwnerId());
		$this->assertSame([''=>$client], $session->getClient());
	}

	public function testCreate()
	{
		$id = $this->session->create('user', '-123', 'myClient', '/myRedirect');

		$this->assertNotNull($id);
		$stmt = $this->db->prepare('SELECT * FROM oauth_sessions WHERE id = ' . $id);
		$stmt->execute();
		$this->assertSame([$id, 'user', '-123', 'myClient', '/myRedirect'], $stmt->fetch(PDO::FETCH_NUM));
	}

	public function testCreateNoRedirect()
	{
		$id = $this->session->create('user', 'myOwner', 'myClient');

		$this->assertNotNull($id);
		$stmt = $this->db->prepare('SELECT * FROM oauth_sessions WHERE id = ' . $id);
		$stmt->execute();
		$this->assertSame([
				'id' => $id,
				'owner_type' => 'user',
				'owner_id' => 'myOwner',
				'client_id' => 'myClient',
				'client_redirect_uri' => null
		], $stmt->fetch(PDO::FETCH_ASSOC));
	}

    public function testCreateFailClientNull()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation).*client_id'");
        $this->session->create('user', 'myOwner', null);
	}

    public function testCreateFailOwnerNull()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation).*owner_id'");
        $this->session->create('user', null, 'myClient');
	}

    public function testCreateFailTypeNull()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation).*owner_type'");
        $this->session->create(null, 'myOwner', 'myClient');
	}

	public function testGetScopes()
	{
		$this->db->exec("INSERT INTO oauth_sessions	VALUES (29, 'user', '3', 'testclient', '/');
						INSERT INTO oauth_scopes VALUES ('user.list', 'list users'), ('user.add', 'add user');
						INSERT INTO oauth_session_scopes VALUES (10, 29, 'user.list');");
		$session = (new SessionEntity($this->server))->setId(29);

		$scopes = $this->session->getScopes($session);

		$this->assertCount(1, $scopes);
		$this->assertEquals('user.list', $scopes[0]->getId());
		$this->assertEquals('list users', $scopes[0]->getDescription());
	}

	public function testGetScopesEmpty()
	{
		$session = (new SessionEntity($this->server))->setId(29);

		$scopes = $this->session->getScopes($session);

		$this->assertCount(0, $scopes);
	}

	public function testAssociateScope()
	{
		$session = (new SessionEntity($this->server))->setId(29);
		$scope = (new ScopeEntity($this->server))->hydrate(['id' => 'user.list', 'description' => 'list user']);

		$this->session->associateScope($session, $scope);

		$stmt = $this->db->prepare('SELECT session_id, scope FROM oauth_session_scopes WHERE session_id = 29');
		$stmt->execute();
		$this->assertSame(['29', 'user.list'], $stmt->fetch(PDO::FETCH_NUM));
	}


	protected function setUp()
	{
		parent::setUp();

		$this->session = new SessionStorage($this->db);
		$this->server = $this->createMock(AbstractServer::class);
		$this->server->method('getEventEmitter')->willReturn(new Emitter());
		$this->clientStorage = $this->getMockBuilder(ClientStorage::class)->disableOriginalConstructor()->getMock();
		$this->server->method('getClientStorage')->willReturn($this->clientStorage);

		$this->session->setServer($this->server);
	}


}
