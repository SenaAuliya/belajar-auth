import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  ParseIntPipe,
} from '@nestjs/common';
import { Request } from 'express';
import { use } from 'passport';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private dbService: PrismaService) {}

  async getMyUser(id: string, req: Request) {
    const user = await this.dbService.user.findUnique({
      where: { id: parseInt(id, 10) },
    });

    if (!user) {
      throw new NotFoundException();
    }

    const decodedUser = req.user as { id: string; email: string };

    if (user.id !== parseInt(decodedUser.id)) {
      throw new ForbiddenException();
    }

    delete user.hashedPassword;
    return { user };
  }

  async getUsers() {
    return await this.dbService.user.findMany({
      select: { id: true, email: true },
    });
  }
}
