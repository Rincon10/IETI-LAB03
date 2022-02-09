## Spring Boot Security with JWT

Secure your REST API using Spring Security with JWT.

**Learning Objectives**

- Explain how JWT works.
- Implement the security of the API endpoints using JWT


## Problem Solving 🤹🏽

Our API Endpoints can be used by anyone that knows the URL and API structure. In order to secure our API we are going to implement JWT authentication. But let's practice our problem solving skills first with the [Bridge Riddle](https://ed.ted.com/lessons/can-you-solve-the-bridge-riddle-alex-gendler#watch) 

**Main Topics**

* Spring Security.
* JWT.
* Token.



## Codelab 🧪


### Part 1: Adding Security Configuration:

1. Add the following dependencies to your *build.gradle*:
   ```groovy
	 implementation 'javax.ws.rs:javax.ws.rs-api:2.0'
     implementation 'org.springframework.boot:spring-boot-starter-security'
     implementation 'org.springframework.security:spring-security-crypto'
     implementation 'io.jsonwebtoken:jjwt:0.9.1'
   ```
2. The following dependencies are optional but helpful if your project isn't recognizing javax features: 
 ```groovy
	 implementation 'javax.ws.rs:javax.ws.rs-api'  
	 implementation 'javax.xml.bind:jaxb-api'
   ```
4. Create a new class inside the *config* package called *SecurityConfiguration* where you will define the secure and open endpoints and the session management policy:

   **Java:**
   ```java
      import org.springframework.http.HttpMethod;
      import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
      import org.springframework.security.config.annotation.web.builders.HttpSecurity;
      import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
      import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
      import org.springframework.security.config.http.SessionCreationPolicy;
      
      @EnableWebSecurity
      @EnableGlobalMethodSecurity( securedEnabled = true, jsr250Enabled = true, prePostEnabled = true )
      public class SecurityConfiguration
          extends WebSecurityConfigurerAdapter
      {
      
      
          @Override
          protected void configure( HttpSecurity http )
              throws Exception
          {
              http.cors().and().csrf().disable()
                  .authorizeRequests()
                  .antMatchers( HttpMethod.GET, "/v1/user" ).permitAll()
                  .antMatchers( HttpMethod.POST,"/v1/user" ).permitAll()
                  .anyRequest().authenticated()
                  .and()
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS );
          }
      }
   ```
 
5. Start your server and verify that the configuration works as expected:

   * Open Endpoint: [User's List](http://localhost:8080/v1/user)
   * Secured Endpoint: [User by Id](http://localhost:8080/v1/user/1)

### Part 2: Implementing the Authentication Controller

1. Create a new package called *auth* inside the *controller* package.
2. Update your *UserDto* to have a new String password property ( don't forget getter ) 
3. Create a new class called *LoginDto* that you will use to map the JSON send to authenticate a user:
    ```java
        public class LoginDto
         {
	         String email;
         
             String password;
         
             public LoginDto( String email, String password )
             {
                 this.email = email;
                 this.password = password;
             }
         
             public String getEmail()
             {
                 return email;
             }
         
             public String getPassword()
             {
                 return password;
             }
         }
     ```
4. Create a new class called *TokenDto* that you will use to return the token and expiration date when the authentication is successful.

   ```java
      public class TokenDto
      {
      
          private String token;
      
          private Date expirationDate;
      
          public TokenDto( String token, Date expirationDate )
          {
              this.token = token;
              this.expirationDate = expirationDate;
          }
      
          public String getToken()
          {
              return token;
          }
      
          public Date getExpirationDate()
          {
              return expirationDate;
          }
      }
   ```
5. Create a *RoleEnum* enum which will have as a possible option the roles **ADMIN** and **USER**
6. Update your *User* class to have a **passwordhash** and **roles** new properties
	```java
	private String passwordHash;
	private List<RoleEnum> roles;
	```
7. Create the corresponding *getter* functions for the new props
8. Generate a hashed password based on the *UserDto* password ( On your *User* constructor which should take as a parameter *UserDto* ) using the BCrypt algorithm:
	```java
	this.passwordHash = BCrypt.hashpw(userDto.getPassword(), BCrypt.gensalt());
	```
9. Also update your *update* function which previously should have been implemented to update a *User* based on a *UserDto* ( If you didn't implement it in this way just refactor your code to match this ):
	```java
	public void update(UserDto user) {
		this.name = user.getName();
		this.email = user.getEmail();
		this.lastName = user.getLastName();
		if (user.getPassword() != null) {
			this.passwordHash = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt());
		}
	}
	```
10. Create *ErrorCodeEnum* to throw the corresponding error message in case there is one:
	```java
	public enum ErrorCodeEnum {
		USER_NOT_FOUND,
		USER_WITH_EMAIL_ALREADY_EXISTS,
		EXPIRED_TOKEN,
		INVALID_USER_CREDENTIALS
	}
	```

11. Create *ServerErrorResponseDto* to structure server error responses:
	```java
	public  class  ServerErrorResponseDto {

		String  message;
		ErrorCodeEnum  errorCode;
		int  httpStatus;

		public  ServerErrorResponseDto(String  message, ErrorCodeEnum  errorCode, HttpStatus  httpStatus) {
			this.message = message;
			this.errorCode = errorCode;
			this.httpStatus = httpStatus.value();
		}
		public  String  getMessage() {
			return  message;
		}
		
		public  ErrorCodeEnum  getErrorCode() {
			return  errorCode;
		}

		public  int  getHttpStatus() {
			return  httpStatus;
		}

	}
	```
12. Create a new exception class inside the *exception* package called *InvalidCredentialsException*:
   ```java
      public class InvalidCredentialsException extends InternalServerErrorException
      {
         public InvalidCredentialsException() {

			super(new ServerErrorResponseDto("User not found", ErrorCodeEnum.USER_NOT_FOUND, HttpStatus.NOT_FOUND),
					HttpStatus.NOT_FOUND);

	     }
      }
   ```
 
13. Create a new *Constants* Class and add the following 2 constants:

	```java
	public class Constants {
		public static final String CLAIMS_ROLES_KEY = "claims";
		// Token expiration defined time
		public static final int TOKEN_DURATION_MINUTES = 60;
	}
	```

14. Add a new environment variable called *SECRET* with a password you'd like to give ( which later will work as the private key ) and then update your *application.properties* file adding the new variable *app.secret*
15. Create a new Rest Controller class inside the *controller.auth* package called *AuthController*

    ```java
	   import io.jsonwebtoken.Jwts;
	   import io.jsonwebtoken.SignatureAlgorithm;
	   import org.ada.school.exception.InvalidCredentialsException;
	   import org.ada.school.repository.document.User;
	   import org.ada.school.service.UserService;
	   import org.springframework.beans.factory.annotation.Autowired;
	   import org.springframework.beans.factory.annotation.Value;
	   import org.springframework.security.crypto.bcrypt.BCrypt;
	   import org.springframework.web.bind.annotation.PostMapping;
	   import org.springframework.web.bind.annotation.RequestBody;
	   import org.springframework.web.bind.annotation.RequestMapping;
	   import org.springframework.web.bind.annotation.RestController;
	   
	   import java.util.Calendar;
	   import java.util.Date;
	   
	   import static co.edu.escuelaing.users.utils.Constants.CLAIMS_ROLES_KEY;
	   import static co.edu.escuelaing.users.utils.Constants.TOKEN_DURATION_MINUTES;
	   
	   @RestController
	   @RequestMapping( "v1/auth" )
	   public class AuthController
	   {
	   
	       @Value( "${app.secret}" )
	       String secret;
	   
	       private final UserService userService;
	   
	       public AuthController( @Autowired UserService userService )
	       {
	           this.userService = userService;
	       }
	   
	       @PostMapping
	       public TokenDto login( @RequestBody LoginDto loginDto )
	       {
	           User user = userService.findByEmail( loginDto.email );
	           if ( BCrypt.checkpw( loginDto.password, user.getPasswordHash() ) )
	           {
	               return generateTokenDto( user );
	           }
	           else
	           {
	               throw new InvalidCredentialsException();
	           }
	   
	       }
	   
	       private String generateToken( User user, Date expirationDate )
	       {
	           return Jwts.builder()
	               .setSubject( user.getId() )
	               .claim( CLAIMS_ROLES_KEY, user.getRoles() )
	               .setIssuedAt(new Date() )
	               .setExpiration( expirationDate )
	               .signWith( SignatureAlgorithm.HS256, secret )
	               .compact();
	       }
	   
	       private TokenDto generateTokenDto( User user )
	       {
	           Calendar expirationDate = Calendar.getInstance();
	           expirationDate.add( Calendar.MINUTE, TOKEN_DURATION_MINUTES );
	           String token = generateToken( user, expirationDate.getTime() );
	           return new TokenDto( token, expirationDate.getTime() );
	       }
	   }
     ```
16. Add the */v1/user/* endpoint temporary to the *SecurityConfiguration* so you can access the endpoint to create a test
   user.
   ```java
    .antMatchers( HttpMethod.POST,"/v1/user" ).permitAll()
   ```
17. Verify the authentication endpoint by sending a user's credentials ( Remember that we have to  add a password to the body now )
18. If everything goes well you would have your token object response with it's corresponding expiration date
    
