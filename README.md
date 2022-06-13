# CS122B Backend 1 - The IDM Service

#### [Application](#application)
 - [pom.xml](#pomxml)
 - [application.yml](#applicationyml)
 - [Resources](#resources)
 - [Tests](#tests)

#### [Database](#database)
 - [Schemas](#schemas)
 - [Tables](#tables)
 - [Initial Data](#initial-data)

#### [Notes](#notes)
 - [Order of Validation](#order-of-validation)
 - [JsonInclude](#jsoninclude)
 - [Result](#result)

#### [Endpoints](#endpoints)
 1. [POST: Register](#register)
 2. [POST: Login](#login)
 3. [POST: Refresh](#refresh)
 4. [POST: Authenticate](#authenticate)

## Application

Our application depends on a lot of files and resources to be able to run correctly. These files have been provided for you and are listed here for your reference. These files should **NEVER** be modified and must be left **AS IS**.

### pom.xml

Maven gets all its settings from a file called `pom.xml`. This file determines the dependencies we will use in our project as well as the plugins we use for compiling, testing, building, ect..

 - [pom.xml](pom.xml)

### application.yml

Spring Boot has a large number of settings that can be set with a file called `application.yml`. We have already created this file for you and have filled it with some settings. There is a file for the main application as well as one for the tests. 

 - [Main application.yml](/src/main/resources/application.yml)
 - [Test application.yml](/src/test/resources/application.yml)

### Resources

There are two folders in this project that contain resources, and application settings, as well as files required for the tests.

 - [Main Resources](/src/main/resources)
 - [Test Resources](/src/test/resources)

### Tests

There is a Single class that contain all of our test cases: 

 - [IDMServiceTest](/src/test/java/com/github/klefstad_teaching/cs122b/idm/IDMServiceTest.java)

## Database

### Schemas

<table>
  <thead>
    <tr>
      <th align="left" width="1100">🗄 idm</th>
    </tr>
  </thead>
</table>

### Tables

<table>
  <thead>
    <tr>
      <th colspan="3" align="left" width="1100">💾 idm.token_status</th>
    </tr>
  </thead>
  <tbody>
    <tr></tr>
    <tr>
      <th align="left" width="175">Column Name</th>
      <th align="left" width="175">Type</th>
      <th align="left">Attributes</th>
    </tr>
    <tr>
      <td>id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code> <code>PRIMARY KEY</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>value</td>
      <td><code>VARCHAR(32)</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
  </tbody>
</table>

<table>
  <thead>
    <tr>
      <th colspan="3" align="left" width="1100">💾 idm.user_status</th>
    </tr>
  </thead>
  <tbody>
    <tr></tr>
    <tr>
      <th align="left" width="175">Column Name</th>
      <th align="left" width="175">Type</th>
      <th align="left">Attributes</th>
    </tr>
    <tr>
      <td>id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code> <code>PRIMARY KEY</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>value</td>
      <td><code>VARCHAR(32)</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
  </tbody>
</table>

<table>
  <thead>
    <tr>
      <th colspan="3" align="left" width="1100">💾 idm.role</th>
    </tr>
  </thead>
  <tbody>
    <tr></tr>
    <tr>
      <th align="left" width="175">Column Name</th>
      <th align="left" width="175">Type</th>
      <th align="left">Attributes</th>
    </tr>
    <tr>
      <td>id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code> <code>PRIMARY KEY</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>name</td>
      <td><code>VARCHAR(32)</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>description</td>
      <td><code>VARCHAR(128)</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>precedence</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
  </tbody>
</table>

<table>
  <thead>
    <tr>
      <th colspan="3" align="left" width="1100">💾 idm.user</th>
    </tr>
  </thead>
  <tbody>
    <tr></tr>
    <tr>
      <th align="left" width="175">Column Name</th>
      <th align="left" width="175">Type</th>
      <th align="left">Attributes</th>
    </tr>
    <tr>
      <td>id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code> <code>PRIMARY KEY</code> <code>AUTO_INCREMENT</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>email</td>
      <td><code>VARCHAR(32)</code></td>
      <td><code>NOT NULL</code> <code>UNIQUE</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>user_status_id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>salt</td>
      <td><code>CHAR(8)</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>hashed_password</td>
      <td><code>CHAR(88)</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr>
      <th colspan="3" align="left">Constraints</th>
    </tr>
    <tr>
      <td colspan="3"><code>FOREIGN KEY</code> <code>(user_status_id)</code> <code>REFERENCES</code> <code>idm.user_status (id)</code> <code>ON UPDATE CASCADE</code> <code>ON DELETE RESTRICT</code></td>
    </tr>
  </tbody>
</table>

<table>
  <thead>
    <tr>
      <th colspan="3" align="left" width="1100">💾 idm.refresh_token</th>
    </tr>
  </thead>
  <tbody>
    <tr></tr>
    <tr>
      <th align="left" width="175">Column Name</th>
      <th align="left" width="175">Type</th>
      <th align="left">Attributes</th>
    </tr>
    <tr>
      <td>id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code> <code>PRIMARY KEY</code> <code>AUTO_INCREMENT</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>token</td>
      <td><code>CHAR(36)</code></td>
      <td><code>NOT NULL</code> <code>UNIQUE</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>user_id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>token_status_id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>expire_time</td>
      <td><code>TIMESTAMP</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>max_life_time</td>
      <td><code>TIMESTAMP</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr>
      <th colspan="3" align="left">Constraints</th>
    </tr>
    <tr>
      <td colspan="3"><code>FOREIGN KEY</code> <code>(user_id)</code> <code>REFERENCES</code> <code>idm.user (id)</code> <code>ON UPDATE CASCADE</code> <code>ON DELETE CASCADE</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td colspan="3"><code>FOREIGN KEY</code> <code>(token_status_id)</code> <code>REFERENCES</code> <code>idm.token_status (id)</code> <code>ON UPDATE CASCADE</code> <code>ON DELETE RESTRICT</code></td>
    </tr>
  </tbody>
</table>

<table>
  <thead>
    <tr>
      <th colspan="3" align="left" width="1100">💾 idm.user_role</th>
    </tr>
  </thead>
  <tbody>
    <tr></tr>
    <tr>
      <th align="left" width="175">Column Name</th>
      <th align="left" width="175">Type</th>
      <th align="left">Attributes</th>
    </tr>
    <tr>
      <td>user_id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td>role_id</td>
      <td><code>INT</code></td>
      <td><code>NOT NULL</code></td>
    </tr>
    <tr>
      <th colspan="3" align="left">Constraints</th>
    </tr>
    <tr>
      <td colspan="3"><code>PRIMARY KEY</code> <code>(user_id, role_id)</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td colspan="3"><code>FOREIGN KEY</code> <code>(user_id)</code> <code>REFERENCES</code> <code>idm.user (id)</code> <code>ON UPDATE CASCADE</code> <code>ON DELETE CASCADE</code></td>
    </tr>
    <tr></tr>
    <tr>
      <td colspan="3"><code>FOREIGN KEY</code> <code>(role_id)</code> <code>REFERENCES</code> <code>idm.role (id)</code> <code>ON UPDATE CASCADE</code> <code>ON DELETE RESTRICT</code></td>
    </tr>
  </tbody>
</table>

### Initial Data

All the data to initialize your database is found in the `db` folder here: [db folder](/db)

# Notes

### Order of Validation
All `❗ 400: Bad Request` Results must be checked first, and returned before any other action is made. \
The order of the checks within `❗ 400: Bad Request` is not tested as each Result is tested individually.

### JsonInclude
In the case of non-successful results, where values are expected, the values should not be included, for example.
```json
{
   "result": {
      "code": 32,
      "message": "Data contains invalid integers"
   },
   "value": null 
}
```
the `value` key should not be included: 
```json
{
   "result": {
      "code": 32,
      "message": "Data contains invalid integers"
   }
}
```
This is done by insuring that all `null` values are dropped by either:
- Having your Model extend `ResponseModel<Model>`, or
- Putting the `@JsonInclude(JsonInclude.Include.NON_NULL)` on your Model class
  
### Result
All `Result` objects are available as static constants inside of the `com.github.klefstad_teaching.cs122b.core.result.IDMResults` class.
These can be used rather than creating your own.

# Endpoints
 
## Register
Allows users to create login details given a valid email and password. Password must be hashed and salted with both values being stored in the `idm.user` table. The user is given no roles, as well as being assigned the `user_status` of `ACTIVE`, by default.

### Path
```http 
POST /register
```

### API

<table>
  <tbody >
    <tr>
      <th colspan="3" align="left" width="1100">📥&nbsp;&nbsp;Request</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
email: String
password: char[]</pre></td>
      <td align="left"><pre lang="json">
{
    "email": "username@example.com",
    "password": ["p", "a", "s", "s", "w", "o", "r", "d"]
}
</pre></td>
    <tr>
      <th align="left">Key</th>
      <th align="left">Required</th>
      <th align="left">Description </th>
    </tr>
    <tr>
      <td><code>email</code></td><td><code>Yes</code></td><td>Must be of the form [email]@[domain].[extension], be between [6-32] characters (inclusive), and contain only alphanumeric characters</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>password</code></td><td><code>Yes</code></td><td>Must be between [10-20] alphanumeric characters (inclusive), contain at least one uppercase alpha, one lowercase alpha, and one numeric</td>
    </tr>
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📤&nbsp;&nbsp;Response</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
result: Result
    code: Integer
    message: String</pre></td>
      <td align="left"><pre lang="json">
{
    "result": {
        "code": 1010,
        "message": "User registered successfully"
    }
}</pre></td>
    </tr>    
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📦&nbsp;&nbsp;Results</th>
    </tr>
    <tr></tr>
    <tr>
      <th align="left" width="200">Status</th>
      <th align="left">Code</th>
      <th align="left">Message</th>
    </tr>
    <tr>
      <td><code>✅ 200: Ok</code></td>
      <td>1010</td>
      <td>User registered successfully</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 409: Conflict</code></td>
      <td>1011</td>
      <td>User with this email already exists</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1000</td>
      <td>Password does not meet length requirements</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1001</td>
      <td>Password does not meet character requirement</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1002</td>
      <td>Email address has invalid format</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1003</td>
      <td>Email address has invalid length</td>
    </tr>
  </tbody>
</table>
      
## Login
Allows users to login with credentials created in the `/register` endpoint. Returns both a `accessToken` and a `refreshToken` (with the `refreshToken` being stored in the `idm.refresh_token` table). Both tokens expiration dates are determined by the values supplied in the `application.yml` file. 

### AccessToken
An `accessToken` is built as follows:
1. Build a `JWTClaimsSet` with the following claims:
    1. `subject` of the user's email
    2. `expirationTime` of the "Current Time" (use Instant for this) + accessTokenExpireTime found in the config
    3. `issueTime` the currentTime
    4. `claim(JWTManager.CLAIM_ROLES)` of the user's roles (user a list of the provided Role enum)
        - If the user has no roles then just place a empty list here. The JWT Requires that there is a value for `JWTManager.CLAIM_ROLES`
    5. `claim(JWTManager.CLAIM_ID)` of the user's id
2. Build a `JWSHeader` with the `JWTManager.JWS_ALGORITHM` and the following:
    1. `keyID` of the ecKeyId found in your instance of `JWTManager`
        - found by calling `manager.getEcKey().getKeyID()`
    2. `type` of `JWTManager.JWS_TYPE`
3. Build a `SignedJWT` with your created `JWTClaimsSet` and `JWSHeader`
4. Sign by using calling `signedJWT.sign(jwtManager.getSigner())`
5. Serialize by calling `signedJWT.serialize()`

### RefreshToken
A `refreshToken` is created by creating an instance of the `RefreshToken` class that is provided for you and having the `token` attribute be set to a random UUID (in string format). You can get a random UUID by using: `UUID.randomUUID()` and you can get the string formated UUID by calling the `toString()` function on the UUID. The token will have a `token_status` of `ACTIVE`, by default. Remember this `refreshToken` must be stored in the `db` to be able to refrence later

The `token` attribute of `RefreshToken` is what you return to the user in the response labeled as `refreshToken`.

### Path
```http 
POST /login
```

### API

<table>
  <tbody>
    <tr>
      <th colspan="3" align="left" width="1100">📥&nbsp;&nbsp;Request</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
email: String
password: char[]</pre></td>
      <td align="left"><pre lang="json">
{
    "email": "username@example.com",
    "password": ["p", "a", "s", "s", "w", "o", "r", "d"]
}
</pre></td>
    <tr>
      <th align="left">Key</th>
      <th align="left">Required</th>
      <th align="left">Description </th>
    </tr>
    <tr>
      <td><code>email</code></td><td><code>Yes</code></td><td>Must be of the form [email]@[domain].[extension], be between [6-32] characters (inclusive), and contain only alphanumeric characters</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>password</code></td><td><code>Yes</code></td><td>Must be between [10-20] alphanumeric characters (inclusive), contain at least one uppercase alpha, one lowercase alpha, and one numeric</td>
    </tr>
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📤&nbsp;&nbsp;Response</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
result: Result
    code: Integer
    message: String
accessToken: String (nullable)
refreshToken: String (nullable)</pre></td>
      <td align="left"><pre lang="json">
{
    "result": {
        "code": 1020,
        "message": "User logged in successfully"
    },
    "accessToken": "7f832c2e054ba732f7d4b7e26..."
    "refreshToken": "c46fc3c2-9791-44d6-a86e-2922ad655284"
}</pre></td>
    </tr>    
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📦&nbsp;&nbsp;Results</th>
    </tr>
    <tr></tr>
    <tr>
      <th align="left" width="200">Status</th>
      <th align="left">Code</th>
      <th align="left">Message</th>
    </tr>
    <tr>
      <td><code>✅ 200: Ok</code></td>
      <td>1020</td>
      <td>User logged in successfully</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 401: Unauthorized</code></td>
      <td>1021</td>
      <td>User not found</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 403: Forbidden</code></td>
      <td>1022</td>
      <td>Passwords do not match</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 403: Forbidden</code></td>
      <td>1023</td>
      <td>User is locked</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 403: Forbidden</code></td>
      <td>1024</td>
      <td>User is banned</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1000</td>
      <td>Password does not meet length requirements</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1001</td>
      <td>Password does not meet character requirement</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1002</td>
      <td>Email address has invalid format</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1003</td>
      <td>Email address has invalid length</td>
    </tr>
  </tbody>
</table>
    
      
## Refresh
Creates a new `accessToken` for the user given a valid and non-expired `refreshToken` that belongs to the user.

### Flowchart
If the `refreshToken` passes basic validation ensure it follows this [Flow Chart](refresh_token_flowchart.svg)

### Path
```http 
POST /refresh
```

### API

<table>
  <tbody>
    <tr>
      <th colspan="3" align="left" width="1100">📥&nbsp;&nbsp;Request</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
refreshToken: String</pre></td>
      <td align="left"><pre lang="json">
{
    "refreshToken": "c46fc3c2-9791-44d6-a86e-2922ad655284"
}
</pre></td>
    <tr>
      <th align="left">Key</th>
      <th align="left">Required</th>
      <th align="left">Description </th>
    </tr>
    <tr>
      <td><code>refreshToken</code></td><td><code>Yes</code></td><td>Must be 36 characters in length and be a valid <code>UUID</code> formatted string</td>
    </tr>
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📤&nbsp;&nbsp;Response</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
result: Result
    code: Integer
    message: String
accessToken: String (nullable)
refreshToken: String (nullable)</pre></td>
      <td align="left"><pre lang="json">
{
    "result": {
        "code": 1030,
        "message": "AccessToken has been refreshed"
    },
    "accessToken": "7f832c2e054ba732f7d4b7e26..."
    "refreshToken": "c46fc3c2-9791-44d6-a86e-2922ad655284"
}</pre></td>
    </tr>    
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📦&nbsp;&nbsp;Results</th>
    </tr>
    <tr></tr>
    <tr>
      <th align="left" width="200">Status</th>
      <th align="left">Code</th>
      <th align="left">Message</th>
    </tr>
    <tr>
      <td><code>✅ 200: Ok</code></td>
      <td>1030</td>
      <td>AccessToken has been refreshed</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 401: Unauthorized</code></td>
      <td>1031</td>
      <td>RefreshToken is expired</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 401: Unauthorized</code></td>
      <td>1032</td>
      <td>RefreshToken is revoked</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 401: Unauthorized</code></td>
      <td>1033</td>
      <td>RefreshToken not found</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1032</td>
      <td>RefreshToken has invalid length</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 400: Bad Request</code></td>
      <td>1033</td>
      <td>RefreshToken has invalid format</td>
    </tr>
  </tbody>
</table>
    
      
## Authenticate
Authenticates a user's `accessToken` to ensure it is both valid and non-expired.

### Verification
An `accessToken` can be verified in three steps:
1. Verifying that the token is valid and issued by us by calling `jwt.verify(jwtManager.getVerifier())`
2. Checking that the claims are consistent with what we expect by calling `jwtManager.getJwtProcessor().process(jwt, null)`
3. Manually checking that the expireTime of the token has not passed.

### Path
```http 
POST /authenticate
```

### API

<table>
  <tbody>
    <tr>
      <th colspan="3" align="left" width="1100">📥&nbsp;&nbsp;Request</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
accessToken: String</pre></td>
      <td align="left"><pre lang="json">
{
    "accessToken": "7f832c2e054ba732f7d4b7e26..."
}
</pre></td>
    <tr>
      <th align="left">Key</th>
      <th align="left">Required</th>
      <th align="left">Description </th>
    </tr>
    <tr>
      <td><code>accessToken</code></td><td><code>Yes</code></td><td>Must be a valid JWT encoded string</td>
    </tr>
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📤&nbsp;&nbsp;Response</th>
    </tr>
    <tr></tr>
    <tr>
      <th colspan="2" align="left">Model </th>
      <th align="left">Example </th>
    </tr>
    <tr>
      <td colspan="2" align="left"><pre lang="yml">
result: Result
    code: Integer
    message: String</pre><td align="left"><pre lang="json">
{
    "result": {
        "code": 1040,
        "message": "AccessToken is valid"
    }
}</pre></td>
    </tr>    
    <tr><td colspan="3" ></td></tr>
    <tr></tr>
    <tr>
      <th colspan="3" align="left">📦&nbsp;&nbsp;Results</th>
    </tr>
    <tr></tr>
    <tr>
      <th align="left" width="200">Status</th>
      <th align="left">Code</th>
      <th align="left">Message</th>
    </tr>
    <tr>
      <td><code>✅ 200: Ok</code></td>
      <td>1040</td>
      <td>AccessToken is valid</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 401: Unauthorized</code></td>
      <td>1041</td>
      <td>AccessToken is expired</td>
    </tr>
    <tr></tr>
    <tr>
      <td><code>❗ 401: Unauthorized</code></td>
      <td>1042</td>
      <td>AccessToken is invalid</td>
    </tr>
  </tbody>
</table>
