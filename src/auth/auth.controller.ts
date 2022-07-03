import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() userData: AuthDto) {
    return this.authService.signup(userData);
  }
  @Post('login')
  login(@Body() credentials: AuthDto): Promise<{ access_token: string }> {
    return this.authService.login(credentials);
  }
}
