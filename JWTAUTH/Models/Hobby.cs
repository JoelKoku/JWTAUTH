using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAUTH.Models
{
    public class Hobby
    {
        public Hobby()
        {
            StudentHobbies = new HashSet<StudentHobby>();
        }
        public int HobbyId { get; set; }
        public string Name { get; set; }
        public ICollection<StudentHobby> StudentHobbies { get; set; }
    }
}
