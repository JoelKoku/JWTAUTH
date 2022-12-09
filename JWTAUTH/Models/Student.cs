using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAUTH.Models
{
    public class Student
    {
        public Student()
        {
            StudentHobbies = new HashSet<StudentHobby>();
        }
        public int StudentId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public int? GenderId { get; set; }

        public Gender Gender { get; set; }
        public ICollection<StudentHobby> StudentHobbies { get; set; }
    }
}
