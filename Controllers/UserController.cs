using Employee_History.Interface;
using Employee_History.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System;
using System.Reflection.Metadata.Ecma335;
using Employee_History.DappaRepo;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Authorization;
using System.Text.Json;

namespace Employee_History.Controllers
{
    
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly IDapperUser dapperUser;
        private readonly IDappaEmployee dappaEmployee;
        private readonly LocationRange locationRange;
        private readonly IConfiguration _configuration;
        private readonly string secretKey;
        public UserController(IDapperUser dapperUser, string secretKey, LocationRange locationRange, IConfiguration configuration,IDappaEmployee dappaEmployee)
        {
            this.dapperUser = dapperUser;
            this.dappaEmployee = dappaEmployee;
            _configuration = configuration;
            this.locationRange = locationRange;
            this.secretKey = secretKey;
        }
        [HttpPost("checkin")]
        public async Task<IActionResult> Checkin([FromBody] User userModel)
        {
            // Retrieve user information
            var user = await dapperUser.AuthenticateAsync(userModel.Staff_ID);
            if (user == null)
            {
                return BadRequest("Invalid Staff ID");
            }

            // Check if device info matches the stored info
            if (user.DeviceID != userModel.DeviceID || user.DeviceModel != userModel.DeviceModel)
            {
                return BadRequest("Device information does not match.");
            }

            // Check if location is within acceptable range
            if (IsLocationInRange(userModel.Longitude, userModel.Latitude))
            {
                return BadRequest("Location is not within acceptable range.");
            }

            // If all checks pass, proceed with check-in
            var attendanceHistory = await dappaEmployee.Checkin(userModel.Staff_ID);
            return Ok("check in successfull");
        }

        private bool IsLocationInRange(decimal longitude, decimal latitude)
        {
            // Use injected LocationRange values
            return longitude >= locationRange.MinLongitude && longitude <= locationRange.MaxLongitude &&
                   latitude >= locationRange.MinLatitude && latitude <= locationRange.MaxLatitude;
        }



        [HttpPost("AddUser")]
        public async Task<IActionResult> AddUser([FromBody] User userModel)
        {
            try
            {
                // Call the repository method to add the user
                var user = await dapperUser.AddUser(userModel.Staff_ID, userModel.Name, userModel.Email, userModel.Phone_number, userModel.Lab_role);
                return Ok("User added succesfully");


            }
            catch (Exception ex)
            {

                Console.WriteLine(ex);

                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpPost("RemoveUser")]
        public async Task<IActionResult> RemoveUser([FromBody] User userModel)
        {
            try
            {
                // Call the repository method to add the user
                var user = await dapperUser.RemoveUser(userModel.Staff_ID);
                return Ok("User removed successfully");

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return StatusCode(500, "An error occurred while processing your request");
            }
        }

        [HttpGet("AddedUsers")]
        public async Task<IEnumerable<User>> GetUsers()
        {
            try
            {
                return await dapperUser.GetUsers();
            }
            catch
            {
                throw;
            }
        }

        [HttpPost("ConfirmPassword")]
        public async Task<IActionResult> ConfirmPassword([FromBody] User userModel)
        {
            try
            {
                // Validate input parameters
                if (string.IsNullOrEmpty(userModel.Staff_ID) || string.IsNullOrEmpty(userModel.Password))
                {
                    return BadRequest("Staff ID and password are required.");
                }

                // Call the repository method to confirm the password
                int result = await dapperUser.ConfirmPassword(userModel.Staff_ID, userModel.Password);

                // Check the result
                if (result == 0)
                {
                    return Ok("Password confirmed successfully.");
                }
                else if (result == -1)
                {
                    return BadRequest("Incorrect password or user not found.");
                }
                else
                {
                    return StatusCode(500, "An error occurred while confirming the password.");
                }
            }
            catch (Exception ex)
            {

                // Return appropriate error response
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        [HttpPost("loginuser")]
        public async Task<IActionResult> Login([FromBody] User userModel)
        {
            try
            {
                // Ensure all required parameters are provided
                if (string.IsNullOrEmpty(userModel.Staff_ID) || string.IsNullOrEmpty(userModel.DeviceID) || string.IsNullOrEmpty(userModel.DeviceModel))
                {
                    return BadRequest("Staff ID, Device ID, and Device Model are required.");
                }

                var user = await dapperUser.AuthenticateAsync(userModel.Staff_ID);

                if (user == null)
                {
                    return BadRequest("Invalid Staff ID");
                }

                var isApproved = await dapperUser.IsUserApprovedAsync(userModel.Staff_ID);
                if (!isApproved)
                {
                    return BadRequest("User is not approved.");
                }

                // If user is approved, store device info
                await dapperUser.StoreDeviceInfo(userModel.Staff_ID, userModel.DeviceID, userModel.DeviceModel);
                
                // Generate JWT token
                var token = JwtTokenGenerator.GenerateToken(user, secretKey);

                return Ok(new { message = "Login successful and device info stored.", token });
            }
            catch (Exception ex)
            {
                return BadRequest("An error occurred during login: " + ex.Message);
            }

        }




        [HttpPost("loginAdmin")]
        public async Task<IActionResult> LoginAdmin([FromBody] User userModel)
        {
            var user = await dapperUser.AdminAuthenticateAsync(userModel.Staff_ID, userModel.Password);

            if (user == null)
            {
                return BadRequest("Invalid Staff ID, Password, or insufficient role.");
            }

            // Generate JWT token
            var token = JwtTokenGenerator.GenerateToken(user, secretKey);

            return Ok(new { message = "Login successful", token });
        }


        [HttpGet("nonapproved")]
        public async Task<IActionResult> GetNonApprovedUsers()
        {
            try
            {
                var nonApprovedUsers = await dapperUser.GetNonApprovedAsync();
                return Ok(nonApprovedUsers);
            }
            catch (Exception ex)
            {
                // Log the exception
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        [HttpPost("approve")]
        public async Task<IActionResult> ApproveUser([FromBody] User userModel)
        {
            try
            {
                var rowsAffected = await dapperUser.ApproveUserAsync(userModel.Staff_ID);
                if (rowsAffected > 0)
                {
                    return Ok("User approval status updated successfully.");
                }
                else
                {
                    return NotFound("User not found or already approved.");
                }
            }
            catch (Exception ex)
            {
                // Log the exception
                return StatusCode(500, "An error occurred while processing your request.");
            }
        }

        [HttpGet("ApprovalHistory")]
        public async Task<IActionResult> GetApprovalData(int daysBehind)
        {
            var approvalData = await dapperUser.GetApprovalDataAsync(daysBehind);
            return Ok(approvalData);
        }

        [HttpGet("DeletionHistory")]
        public async Task<IActionResult> GetRemovalData(int daysBehind)
        {
            var removalData = await dapperUser.GetRemovalDataAsync(daysBehind);
            return Ok(removalData);
        }

        [HttpGet("employeesByRole")]
        public async Task<IActionResult> GetEmployeesByRoleID(string Lab_role)
        {
            try
            {
                var employees = await dapperUser.GetEmployeesByRoleIDAsync(Lab_role);
                return Ok(employees);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }



    }
}
