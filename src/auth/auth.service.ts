import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from '../utils/constants';
import { request, response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private dbService: PrismaService,
    private jwt: JwtService,
  ) {}

  async signUp(dto: AuthDto) {
    const { email, password } = dto;

    const foundUser = await this.dbService.user.findUnique({
      where: { email },
    });

    if (foundUser) {
      throw new BadRequestException('Email Sudah Ada');
    }

    const hashedPassword = await this.hashPassword(password);

    await this.dbService.user.create({
      data: {
        email,
        hashedPassword,
      },
    });

    return { message: 'signup berhasil' };
  }
  async signIn(dto: AuthDto, req = request, res = response) {
    const { email, password } = dto;

    const foundUser = await this.dbService.user.findUnique({
      where: { email },
    });

    if (!foundUser) {
      throw new BadRequestException('Email Belum Ada');
    }

    const isMatch = await this.comparePasswords({
      password,
      hash: foundUser.hashedPassword,
    });

    if (!isMatch) {
      throw new BadRequestException('Sandi Salah');
    }

    const token = await this.signToken({
      id: foundUser.id,
      email: foundUser.email,
    });

    if (!token) {
      throw new ForbiddenException();
    }

    res.cookie('token', token);
    return res.send({ message: 'Berhasil Log In' });
  }
  async signOut(req = request, res = response) {
    res.clearCookie('token');
    return res.send({ message: 'Berhasil Log Out' });
  }

  async hashPassword(password: string) {
    const saltOrRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltOrRounds);
    return hashedPassword;
  }

  async comparePasswords(args: { password: string; hash: string }) {
    return await bcrypt.compare(args.password, args.hash);
  }

  async signToken(args: { id: number; email: string }) {
    const { id, email } = args;
    const payload = { sub: id.toString(), email };

    return this.jwt.signAsync(payload, { secret: jwtSecret });
  }
}
