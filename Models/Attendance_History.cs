﻿using System.ComponentModel.DataAnnotations;

namespace Employee_History.Models
{
    public class Attendance_History
    {
        [Key]
        public string Staff_ID { get; set; } = string.Empty;
        public string? EntryTime { get; set; }
        public string? ExitTime { get; set; }
        public DateTime Date { get; set; }
        public int Month { get; set; } 
        public int Year { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
    }
}
