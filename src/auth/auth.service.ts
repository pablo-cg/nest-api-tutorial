import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signup(userData: AuthDto) {
    try {
      // pw gen
      const hash = await argon.hash(userData.password);

      //save the new user
      const newUser = await this.prisma.user.create({
        data: {
          email: userData.email,
          hash,
        },
      });

      //return new user
      delete newUser.hash;
      return newUser;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        switch (error.code) {
          case 'P2002':
            throw new ForbiddenException('User already exist');
        }
      }
    }
  }

  async login(credentials: AuthDto) {
    // find user by email, throw exception if not exist
    const user = await this.prisma.user.findUnique({
      where: {
        email: credentials.email,
      },
    });

    if (!user) throw new ForbiddenException('Incorrect Credentials');

    // compare pw, if incorrect throw exception
    const passwordMatch = await argon.verify(user.hash, credentials.password);

    if (!passwordMatch) throw new ForbiddenException('Incorrect Credentials');

    // return the user jwt
    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: string,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const options: JwtSignOptions = {
      expiresIn: '15m',
      secret: this.config.get('JWT_SECRET'),
    };

    const token = await this.jwt.signAsync(payload, options);

    return {
      access_token: token,
    };
  }
}
