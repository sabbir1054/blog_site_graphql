
import bcrypt from "bcrypt";
import jwt, { Secret } from "jsonwebtoken";
import config from "../../config";



interface userInfo {
  name: string;
  email: string;
  password: string;
}
interface loginInfo {
  email: string;
  password: string;
}
export const Mutation = {
  signup: async (parent: any, args: userInfo, { prisma }: any) => {
    const hashedPassword = await bcrypt.hash(args.password, 12);
    const newData = {
      name: args.name,
      email: args.email,
      password: hashedPassword,
    };
    const newUser = await prisma.user.create({ data: newData });
    const token = await jwt.sign(
      { userId: newUser?.id, email: newUser?.email },
      config.jwt.secret as Secret,
      { expiresIn: "1d" }
    );

    return { token };
  },
  signin: async (parent: any, args: loginInfo, { prisma }: any) => {
    const isExistUser = await prisma.user.findFirst({
      where: {
        email: args?.email,
      },
    });
    if (!isExistUser) {
      return {
        token: null,
      };
    }
    const isPasswordValid = await bcrypt.compare(
      args.password,
      isExistUser?.password
    );
    if (!isPasswordValid) {
      return {
        token: null,
      };
    }

    const token = await jwt.sign(
      { userId: isExistUser?.id, email: isExistUser?.email },
      config.jwt.secret as Secret,
      { expiresIn: "1d" }
    );

    return {
      token,
    };
  },
};
