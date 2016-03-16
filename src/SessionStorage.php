<?php
/**
 * Created by IntelliJ IDEA.
 * User: david
 * Date: 16.03.16
 * Time: 10:08
 */

namespace DBoho\OAuth2\Server\Storage\PDO;


use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Storage\SessionInterface;
use PDO;

class SessionStorage extends Storage implements SessionInterface
{
	/**
	 * Get a session from an access token
	 *
	 * @param \League\OAuth2\Server\Entity\AccessTokenEntity $accessToken The access token
	 *
	 * @return \League\OAuth2\Server\Entity\SessionEntity | null
	 */
	public function getByAccessToken(AccessTokenEntity $accessToken)
	{
		$stmt = $this->pdo->prepare('SELECT id, owner_type, owner_id, client_id, client_redirect_uri
									FROM oauth_sessions as oauth_sessions JOIN oauth_access_tokens as tokens ON(tokens.session_id = id)
									WHERE tokens.access_token = :accessTokenId');
		$stmt->bindValue(':accessTokenId', $accessToken->getId());
		$stmt->execute();
		$result = $stmt->fetchAll();
		if (count($result) === 1) {
			$session = new SessionEntity($this->getServer());
			$session->setId($result[0]['id']);
			$session->setOwner($result[0]['owner_type'], $result[0]['owner_id']);
			return $session;
		}
		return null;
	}

	/**
	 * Get a session from an auth code
	 *
	 * @param \League\OAuth2\Server\Entity\AuthCodeEntity $authCode The auth code
	 *
	 * @return \League\OAuth2\Server\Entity\SessionEntity | null
	 */
	public function getByAuthCode(AuthCodeEntity $authCode)
	{
		$stmt = $this->pdo->prepare('SELECT id, owner_type, owner_id
									FROM oauth_sessions as s JOIN oauth_auth_codes as codes ON(codes.session_id = id)
									WHERE codes.auth_code = :auth_code');
		$stmt->bindValue(':auth_code', $authCode->getId());
		$stmt->execute();
		$result = $stmt->fetchAll();
		if (count($result) === 1) {
			$session = new SessionEntity($this->getServer());
			$session->setId($result[0]['id']);
			$session->setOwner($result[0]['owner_type'], $result[0]['owner_id']);
			return $session;
		}
		return null;
	}

	/**
	 * Create a new session
	 *
	 * @param string $ownerType SessionStorage owner's type (user, client)
	 * @param string $ownerId SessionStorage owner's ID
	 * @param string $clientId Client ID
	 * @param string $clientRedirectUri Client redirect URI (default = null)
	 *
	 * @return integer The session's ID
	 */
	public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null)
	{
		$stmt = $this->pdo->prepare('INSERT INTO oauth_sessions (owner_type, owner_id, client_id, client_redirect_uri)
							VALUES (?,?,?,?)');
		$stmt->execute([$ownerType, $ownerId, $clientId, $clientRedirectUri]);
		return $this->pdo->lastInsertId();
	}

	/**
	 * Get a session's scopes
	 *
	 * @param  \League\OAuth2\Server\Entity\SessionEntity
	 *
	 * @return \League\OAuth2\Server\Entity\ScopeEntity[] Array of \League\OAuth2\Server\Entity\ScopeEntity
	 */
	public function getScopes(SessionEntity $session)
	{
		$stmt = $this->pdo->prepare('SELECT scope.* FROM oauth_sessions as sess
							 JOIN oauth_session_scopes as ss ON(ss.session_id=sess.id)
							 JOIN oauth_scopes as scope ON(scope.id=ss.scope)
							 WHERE sess.id = :sessionId');
		$stmt->bindValue(':sessionId', $session->getId());
		$stmt->execute();
		$results = $stmt->fetchAll(PDO::FETCH_ASSOC);
		$scopes = [];
		foreach ($results as $scope) {
			$scopes[] = (new ScopeEntity($this->server))->hydrate([
					'id' => $scope['id'],
					'description' => $scope['description'],
			]);
		}
		return $scopes;
	}

	/**
	 * Associate a scope with a session
	 *
	 * @param \League\OAuth2\Server\Entity\SessionEntity $session The session
	 * @param \League\OAuth2\Server\Entity\ScopeEntity $scope The scope
	 *
	 * @return void
	 */
	public function associateScope(SessionEntity $session, ScopeEntity $scope)
	{
		$stmt = $this->pdo->prepare('INSERT INTO oauth_session_scopes (session_id, scope) VALUES (?,?)');
		$stmt->execute([$session->getId(), $scope->getId()]);
	}
}