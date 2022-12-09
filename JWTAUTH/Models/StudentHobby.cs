using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAUTH.Models
{
    public class StudentHobby
    {
        public int StudentId { get; set; }
        public int HobbyId { get; set; }
        public Student Student { get; set; }
        public Hobby Hobby { get; set; }
    }
}
