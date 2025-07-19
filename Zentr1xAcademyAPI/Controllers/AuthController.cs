using Domain.Entities;
using Infrastructure.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.Design.Serialization;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Zentr1xAcademyAPI.Dtos;

namespace Zentr1xAcademyAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration configuration;
        private readonly AppDbContext _context;

        public AuthController(
            UserManager<User> userManager, 
            RoleManager<IdentityRole> roleManager, 
            IConfiguration configuration, 
            AppDbContext context) 
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            this.configuration = configuration;
            _context = context;
        }

        // -----------------------
        // ADMIN REGISTER (assign any role)
        // -----------------------

        [HttpPost("register")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Register (RegisterDto dto)
        {
            var existing = await userManager.FindByEmailAsync(dto.Email);
            if (existing != null) return BadRequest("User Already exists!");

            var user = new User
            {
                UserName = dto.UserName,
                Email = dto.Email,
                FirstName = dto.FirstName,
                MiddleName = dto.MiddleName,
                LastName = dto.LastName,
                Birthday = dto.Birthday,
                PhoneNumber = dto.PhoneNumber
            };

            var result = await userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            if (!await roleManager.RoleExistsAsync(dto.Role))
                await roleManager.CreateAsync(new IdentityRole(dto.Role));

            await userManager.AddToRoleAsync(user, dto.Role);
            return Ok("User registered with role: " + dto.Role);
        }

        // -----------------------
        // PUBLIC REGISTER (default = Student)
        // -----------------------

        [HttpPost("public-register")]
        public async Task<IActionResult> PublicRegister(PublicRegisterDto dto)
        {
            var existing = userManager.FindByEmailAsync(dto.Email);
            if (existing != null) return BadRequest("User Already Exists!");

            var user = new User
            {
                UserName = dto.UserName,
                Email = dto.Email,
                FirstName = dto.FirstName,
                MiddleName = dto.MiddleName,
                LastName = dto.LastName,
                Birthday = dto.Birthday,
                PhoneNumber = dto.PhoneNumber
            };

            var result = await userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded) return BadRequest(result.Errors);

            if (!await roleManager.RoleExistsAsync("Student"))
                await roleManager.CreateAsync(new IdentityRole("Student"));

            await userManager.AddToRoleAsync(user, "Student");
            return Ok("Registered successfully as Student");
        }

        // -----------------------
        // LOGIN
        // -----------------------

        [HttpPost("login")]
        public async Task<IActionResult> Login (LoginDto dto)
        {
            User user;
            // username / email
            user = await userManager.FindByNameAsync(dto.Identifier);
            if (user == null)
                user = await userManager.FindByEmailAsync(dto.Identifier);

            if (user == null || !await userManager.CheckPasswordAsync(user, dto.Password))
                return Unauthorized("Invalid credentials");

            var roles = await userManager.GetRolesAsync(user);
            var accessToken = GenerateJwtToken(user, roles);     // expired in 15 - 30 minutes
            var refreshToken = await GenerateRefreshToken(user); // expired in 7 - 30 days 365+
            //
            return Ok(new
            {
                token = accessToken,
                refreshToken = refreshToken.Token,
                expires = DateTime.UtcNow.AddMinutes(15),
                role = roles.FirstOrDefault(),
                userId = user.Id,
                fullName = user.FullName
            });
        }

        // -----------------------
        // REFRESH TOKEN
        // -----------------------

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenRefreshRequest request)
        {
            var storedToken = _context.RefreshTokens
                .Where(x => x.Token == request.RefreshToken)
                .OrderByDescending(x => x.Created)
                .FirstOrDefault();

            if (storedToken == null || !storedToken.IsActive)
                return Unauthorized("Invalid or expired refresh token");

            storedToken.Revoked = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            var user = await userManager.FindByIdAsync(storedToken.UserId);
            var roles = await userManager.GetRolesAsync(user);
            var newAccessToken = GenerateJwtToken(user, roles);
            var newRefreshToken = await GenerateRefreshToken(user);

            return Ok(new
            {
                token = newAccessToken,
                refreshToken = newRefreshToken.Token,
                expires = DateTime.UtcNow.AddMinutes(15),
                role = roles.FirstOrDefault(),
                userId = user.Id,
                fullName = user.FullName
            });
        }









        private string GenerateJwtToken(User user, IList<string> roles)
        {
            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            foreach (var role in roles)
                claims.Add(new Claim(ClaimTypes.Role, role));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: configuration["JWT:Issuer"],
                audience: configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // -----------------------
        // Generate Refresh Token
        // -----------------------
        private async Task<RefreshToken> GenerateRefreshToken(User user)
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                UserId = user.Id
            };

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return refreshToken;
        }
    }
}
