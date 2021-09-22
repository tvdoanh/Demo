using System.ComponentModel.DataAnnotations;

namespace ExternalAuth.ViewModels
{
    public class LocalLoginViewModel
    {
        //[Required(ErrorMessage = "MSG_FIELD_REQUIRED")]
        //[EmailAddress(ErrorMessage = "MSG_EMAIL_FORMAT_INVALID")]
        //public string Email { get; set; }

        [Required()]
        [Display(Name = "Tài khoản")]
        public string Username { get; set; }

        [Required()]
        [DataType(DataType.Password)]
        [Display(Name = "Mật khẩu")]
        public string Password { get; set; }

        [Display(Name = "Nhớ tài khoản")]
        public bool RememberLogin { get; set; }

        public string ReturnUrl { get; set; }
    }
}
