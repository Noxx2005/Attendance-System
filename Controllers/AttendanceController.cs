﻿using Employee_History.DappaRepo;
using Employee_History.Models;
using Microsoft.AspNetCore.Mvc;
using Employee_History.Interface;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using MimeKit.Cryptography;

namespace Employee_History.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AttendanceController : Controller
    {
        private readonly IDappaEmployee dappaEmployee;

        public AttendanceController(IDappaEmployee dappaEmployee)
        {
            this.dappaEmployee = dappaEmployee;
        }
        
        [HttpGet("AttendanceHistory")]
        public async Task<IActionResult> GetAttendance()
        {
            try
            {
                var result = await dappaEmployee.GetAttendance();
                return Ok(result);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
       
        [HttpPost("AttendanceByID")]
        public async Task<Attendance_History> GetAttendanceByID([FromBody] Attendance_History history)
        {
            try
            {
                var response = await dappaEmployee.GetAttendanceByID(history.Staff_ID);
                return response ?? null;
            }
            catch (Exception ex)
            {
                // Log exception if necessary
                Console.WriteLine(ex);
                return null; // Return null to maintain the original method signature
            }
        }
        
        [HttpPost("AttendanceByDate")]
        public async Task<IEnumerable<Attendance_History>> GetAttendanceByDate([FromBody] Attendance_History history)
        {
            try
            {
                var response = await dappaEmployee.GetAttendanceByDate(history.Date);
                return response ?? null;
            }
            catch (Exception ex)
            {
                // Log exception if necessary
                Console.WriteLine(ex);
                return null; // Return null to maintain the original method signature
            }
        }
       
        [HttpPost("GetAttendanceByIDandDate")]
        public async Task<Attendance_History> GetAttendanceByIDandDate([FromBody] Attendance_History history)
        {
            try
            {
                var response = await dappaEmployee.GetAttendanceByIDandDate(history.Staff_ID, history.Date);
                return response ?? null;
            }
            catch (Exception ex)
            {
                // Log exception if necessary
                Console.WriteLine(ex);
                return null; // Return null to maintain the original method signature
            }
        }
       
        [HttpPost("GetAttendanceByIDbtwDates")]
        public async Task<IEnumerable<Attendance_History>> GetAttendanceByIDbtwDates([FromBody] Attendance_History history)
        {
            try
            {
                var response = await dappaEmployee.GetAttendanceByIDbtwDates(history.Staff_ID, history.StartDate, history.EndDate);
                return response ?? null;
            }
            catch (Exception ex)
            {
                // Log exception if necessary
                Console.WriteLine(ex);
                return null; // Return null to maintain the original method signature
            }
        }
      
        [HttpPost("GetAttendancebtwDates")]
        public async Task<IEnumerable<Attendance_History>> GetAttendancebtwDates([FromBody] Attendance_History history)
        {
            try
            {
                var response = await dappaEmployee.GetAttendancebtwDates(history.StartDate, history.EndDate);
                return response ?? null;
            }
            catch (Exception ex)
            {
                // Log exception if necessary
                Console.WriteLine(ex);
                return null; // Return null to maintain the original method signature
            }
        }
       
        [HttpPut("Checkout")]
        public async Task<IActionResult> Checkout([FromBody] Attendance_History history)
        {
            try
            {
              var outtime=  await dappaEmployee.Checkout(history.Staff_ID);
                return Ok(outtime);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                return StatusCode(500, "An error occurred while updating exit time");
            }
        }
      
        [HttpPost("Latecheckin")]
        public async Task<IEnumerable<Attendance_History>> GetLateCheckinStaffAsync()
        {
            try
            {
                return await dappaEmployee.GetLateCheckinStaffAsync();
            }
            catch (Exception ex)
            {
                // Log exception if necessary
                Console.WriteLine(ex);
                return null; // Return null to maintain the original method signature
            }
        }
    }
}
