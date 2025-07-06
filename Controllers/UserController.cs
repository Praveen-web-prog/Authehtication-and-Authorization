using Azure.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using MyAuthentication.Models;
using MyAuthentication.Models.Entities;
using System.Data.SqlTypes;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace MyAuthentication.Controllers
{
    [ApiController]
    [Route("api/UserData")]
    public class UserController(IConfiguration configuration) : Controller
    {
        private int countExsistingUser;
        private bool _IsDbExsist = true;

        // user -> Modle/Entity
        private User OriginalUser = new User();

        // object to read the Data from the Db
        UserDto readingObject;
        private string? issuer;

        [HttpPost("register")]
        public IActionResult Register(UserDto user)
        {
        // idhu vandhu user edhumea enter pannalana
            if (user.UserName == null || user.Password == null)
                return BadRequest("Incorrect UserName or Password");

            // ippo already exsisting Name ah enter panna -> ippo adhuku oru condition
            CheckDb(user);
            
            
            if (countExsistingUser > 0)
            {
                return BadRequest("Already Exsisting UserName !");
            }

            user.Password = new PasswordHasher<UserDto>().
                                 HashPassword(user,user.Password);

            OriginalUser.UserName = user.UserName;
            OriginalUser.Password = user.Password;

            // ippo namma Db la UserName and Password ah store panna porom
            StoreDb(OriginalUser);

          return Ok("Your UserName and Passowrd Has been Registered Successfully !");
        }


        [HttpPost("login")]
        public IActionResult Login(UserDto user)
        {
            // inga vandhu User login panna try pannumbodhu wrong userName ah irruka illaya nu check pannanu 
            // adhku namma Db la check pannanu 
            using (SqlConnection sqlConnection = new SqlConnection(configuration.GetConnectionString("DefaultConnection")))
            {
                sqlConnection.Open(); // idhu vandhu Database ah open pannudhu , ok va (Table ah Open pannala )

                string sqlString = @"
                  SELECT * FROM AuthUserDb
                  WHERE UserName = @UserName
                ";

                using (SqlCommand cmd = new SqlCommand(sqlString, sqlConnection))
                {
                    cmd.Parameters.AddWithValue("@UserName", user.UserName);

                    // multiple values -> Db la irrundhu return aaganu na -> namma -> enna pannuvom 
                    // easy -> ExecuteReader()
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            string UserNameIn = reader.GetString(1);
                            string PasswordIn = reader.GetString(2);

                            readingObject = new UserDto()
                            {
                                UserName = UserNameIn,
                                Password = PasswordIn
                            };
                        }
                    }

                    cmd.ExecuteNonQuery();
                }

            }



            PasswordVerificationResult passwordHashed = new PasswordHasher<UserDto>()
                               .VerifyHashedPassword(user, readingObject.Password, user.Password);


            // Db la irruka UserName and Password enter pandradhum same ah irruka nu check pandrom
            if (user.UserName != readingObject.UserName)
                return BadRequest("Incorrect UserName or Password !");
                                 // idhu vandhu enum actual ah
            if (passwordHashed == PasswordVerificationResult.Failed)
                return BadRequest("Incorrect UserName or Password");

            // token vechu Authentication pannalam 
            string token = CreateToken(user);


            return Ok(token);
        }


        // securred endpoint
        [Authorize]
        [HttpGet("auth")]
        public IActionResult AuthUserOnly()
        {

            return Ok("You're Authorized !");
        }










        private string CreateToken(UserDto user)
        {
            var claims = new[]
            { 
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.UserName)
            };

            var key = new SymmetricSecurityKey(
                     Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));

            //var key = new SymmetricSecurityKey(
            //    Encoding.UTF8.GetBytes(configuration.GetValue<string>("AppSettings:Token")!));


            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new JwtSecurityToken(
                issuer : configuration.GetValue<string>("AppSettings:Issuer"),
                audience : configuration.GetValue<string>("AppSettings:Audience"),
                claims : claims,
                expires : DateTime.UtcNow.AddDays(1),
                signingCredentials : creds
            );


            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }

        private void createTable()
        {
            using (SqlConnection sqlConnection = new SqlConnection(configuration.GetConnectionString("DefaultConnection")))
            {
                sqlConnection.Open();

                string sqlString = @"
                    IF NOT EXISTS (
                SELECT * FROM sysobjects 
                WHERE name='AuthUserDb' 
            )
            BEGIN
                CREATE TABLE AuthUserDb (
                    Id UNIQUEIDENTIFIER PRIMARY KEY,
                    UserName VARCHAR(200),
                    Password VARCHAR(200)
                )
            END
                ";

                using (SqlCommand cmd = new SqlCommand(sqlString,sqlConnection))
                {
                    cmd.ExecuteNonQuery();

                   
                }
            }
        }



        private void CheckDb(UserDto user)
        {
            if (_IsDbExsist)
            {
                createTable();
                _IsDbExsist = false;
            }

            using (SqlConnection sqlConnection = new SqlConnection(configuration.GetConnectionString("DefaultConnection")))
            {
                sqlConnection.Open();

                string sqlString = @"
                  SELECT COUNT(*) FROM AuthUserDb
                  WHERE UserName = @UserName 
                ";

                using (SqlCommand cmd = new SqlCommand(sqlString, sqlConnection))
                {
                    cmd.Parameters.AddWithValue("@UserName", user.UserName);

                    // to retrive the single value from the table
                    countExsistingUser = (int)cmd.ExecuteScalar();


                    // this is to execute the query 
                    cmd.ExecuteNonQuery();
                }
            }
        }



        private void StoreDb(User user)
        {
            using (SqlConnection sqlConnection = new SqlConnection(configuration.GetConnectionString("DefaultConnection")))
            {
                Guid Id = Guid.NewGuid();

                sqlConnection.Open();

                string sqlString = @"
                 INSERT INTO AuthUserDb(Id , UserName , Password)
                 VALUES(@Id , @UserName , @Password)
                ";

                using (SqlCommand cmd = new SqlCommand(sqlString, sqlConnection))
                {
                    cmd.Parameters.AddWithValue("@Id", Id);
                    cmd.Parameters.AddWithValue("@UserName", user.UserName);
                    cmd.Parameters.AddWithValue("@Password", user.Password);
                    
                    // this is to execute the query 
                    cmd.ExecuteNonQuery();
                }
            }
        }



    }
}
