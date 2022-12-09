using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAUTH.Models
{
    public class Gender
    {
        public Gender()
        {
            Students = new HashSet<Student>();
        }
        public int GenderId { get; set; }
        public string Name { get; set; }
        public ICollection<Student> Students { get; set; }
    }
}
