using System.Security.Cryptography;
using System.Text;
using AutoMapper;
using courses_dotnet_api.Src.DTOs.Account;
using courses_dotnet_api.Src.Interfaces;
using courses_dotnet_api.Src.Models;
using Microsoft.EntityFrameworkCore;

namespace courses_dotnet_api.Src.Data;

public class AccountRepository : IAccountRepository
{
    private readonly DataContext _dataContext;
    private readonly IMapper _mapper;
    private readonly ITokenService _tokenService;

    public AccountRepository(DataContext dataContext, IMapper mapper, ITokenService tokenService)
    {
        _dataContext = dataContext;
        _mapper = mapper;
        _tokenService = tokenService;
    }

    public async Task AddAccountAsync(RegisterDto registerDto)
    {
        using var hmac = new HMACSHA512();

        User user =
            new()
            {
                Rut = registerDto.Rut,
                Name = registerDto.Name,
                Email = registerDto.Email,
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

        await _dataContext.Users.AddAsync(user);
    }

    public async Task<AccountDto?> GetAccountAsync(string email)
    {
        User? user = await _dataContext
            .Users.Where(student => student.Email == email)
            .FirstOrDefaultAsync();

        if (user == null)
        {
            return null;
        }

        AccountDto accountDto =
            new()
            {
                Rut = user.Rut,
                Name = user.Name,
                Email = user.Email,
                Token = _tokenService.CreateToken(user.Rut)
            };

        return accountDto;
    }

    public async Task<bool> SaveChangesAsync()
    {
        return 0 < await _dataContext.SaveChangesAsync();
    }

    public async Task<bool> verifyCredentials(LoginDto loginDto){

        //seach a user using de dataBase
        var userLoger = await _dataContext.Users.Where(u => u.Email == loginDto.Email).FirstOrDefaultAsync();
        //the user don't exist
        if(userLoger == null) return false; //return false

        //using hmac already encrypted
        using var hmac = new HMACSHA512(userLoger.PasswordSalt);

        //encript the password
        byte[] PasswordHashed = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
        
        //try the password if is diferent
        for (int i = 0; i < PasswordHashed.Length; i++)
        {
            if (PasswordHashed[i] != userLoger.PasswordHash[i])
                return false;
        }
        //all hashed are same, thus return true
        return true;
    }
}
