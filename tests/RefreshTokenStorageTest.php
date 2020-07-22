<?php
use DBoho\OAuth2\Server\Storage\PDO\AccessTokenStorage;
use DBoho\OAuth2\Server\Storage\PDO\RefreshTokenStorage;
use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;

/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 16.03.16
 * Time: 21:05
 */
class RefreshTokenStorageTest extends PDOTest
{
	/**
	 * @var RefreshTokenStorage
	 */
	protected $token;
	/**
	 * @var AbstractServer
	 */
	protected $server;
	/**
	 * @var PHPUnit_Framework_MockObject_MockObject
	 */
	protected $accessStorage;

	public function testGetFailed()
	{
		$authCode = $this->token->get('unknwon');

		$this->assertNull($authCode);
	}

	public function testGet()
	{
		$time = time() + 60 * 60;
		$this->db->exec("INSERT INTO oauth_refresh_tokens VALUES ('10Refresh', " . $time . ", '10Access');");
		$accessToken = new AccessTokenEntity($this->server);
        /** @noinspection PhpParamsInspection */
        $this->accessStorage->expects($this->once())->method('get')->with('10Access')->willReturn($accessToken);

		$authCode = $this->token->get('10Refresh');

		$this->assertNotNull($authCode);
		$this->assertEquals('10Refresh', $authCode->getId());
		$this->assertEquals($time, $authCode->getExpireTime());
		$this->assertEquals($accessToken, $authCode->getAccessToken());
	}

	public function testCreate()
	{
		$time = time() + 60 * 60;
		$this->token->create('20NewToken', $time, "20Access");

		$stmt = $this->db->prepare("SELECT * FROM oauth_refresh_tokens WHERE refresh_token = '20NewToken'");
		$stmt->execute();
		$this->assertSame([
				'refresh_token' => '20NewToken',
				'expire_time' => (string) $time,
				'access_token' => '20Access'
		], $stmt->fetch(PDO::FETCH_ASSOC));
	}

    public function testCreateFailedNoAccessToken()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*access_token'");
        $this->token->create('20NewToken', 1024, null);
	}

    public function testCreateFailedNoExpired()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*expire_time'");
        $this->token->create('20NewToken', null, "20AccessToken");
	}

    public function testCreateFailedNoCode()
	{
        $this->expectException(PDOException::class);
        $this->expectExceptionMessageRegExp("'.*constraint (failed|violation):.*refresh_token'");
        $this->token->create(null, 1024, 1);
	}

	public function testDelete()
	{
		$this->db->exec("INSERT INTO oauth_refresh_tokens
					VALUES ('10Refresh', DATETIME('NOW', '+1 DAY'), '10Access');");
		$token = (new RefreshTokenEntity($this->server))->setId('10Refresh');

		$this->token->delete($token);

		$stmt = $this->db->prepare("SELECT * FROM oauth_refresh_tokens WHERE refresh_token = '10Refresh'");
		$stmt->execute();
		$this->assertSame([], $stmt->fetchAll(PDO::FETCH_ASSOC));
	}

	protected function setUp()
	{
		parent::setUp();
		$this->token = new RefreshTokenStorage($this->db);
		$this->server = $this->createMock(AbstractServer::class);
		$this->accessStorage = $this->getMockBuilder(AccessTokenStorage::class)->disableOriginalConstructor()->getMock();
		$this->server->method('getAccessTokenStorage')->willReturn($this->accessStorage);

		$this->token->setServer($this->server);
	}

}
