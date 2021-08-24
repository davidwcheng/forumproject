import { MyContext } from "src/types";
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Query,
  Resolver,
} from "type-graphql";
import { User } from "../entities/User";
import argon2 from "argon2";
import { __COOKIE__ } from "../constants";

@InputType()
class UsernamePasswordInput {
  @Field()
  username: string;
  @Field()
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;
  @Field()
  message: string;
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];

  @Field(() => User, { nullable: true })
  user?: User;
}
// lemme just double check
@Resolver()
export class UserResolver {
  @Query(() => User, { nullable: true })
  async me(@Ctx() { req, em }: MyContext) {
    console.log(req.session.userId);
    console.log(req.session);

    if (!req.session.userId) {
      return null;
    }
    console.log(`User's id is ${req.session.userId}`);
    // he switches from mikrorm to typeorm later in the video, just a heads up
    const user = await em.findOne(User, { id: req.session.userId });
    return user;
  }

  @Mutation(() => UserResponse)
  async register(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    if (options.username.length <= 2) {
      return {
        errors: [
          {
            field: "username",
            message: "username is too short, length of 3 or more",
          },
        ],
      };
    }

    if (options.password.length <= 3) {
      return {
        errors: [
          {
            field: "password",
            message: "password is too short, length of 4 or more",
          },
        ],
      };
    }

    const hashedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      password: hashedPassword,
    });
    try {
      await em.persistAndFlush(user);
    } catch (e) {
      //duplicate username
      if (e.detail.includes("already exists")) {
        return {
          errors: [
            {
              field: "username",
              message: "that username already exists",
            },
          ],
        };
      }
    }
    req.session.userId = user.id;

    return { user };
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, { username: options.username });
    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "invalid login, try again",
          },
        ],
      };
    }
    const valid = await argon2.verify(user.password, options.password);
    if (!valid) {
      return {
        errors: [
          {
            field: "password",
            message: "invalid login, try again",
          },
        ],
      };
    }

    console.log("Logged in");

    req.session.userId = user.id;

    console.log(`Req ${req.session.userId}`);

    return { user };
  }

  @Mutation(() => Boolean)
  logout(@Ctx() { req, res }: MyContext) {
    return new Promise((resolved) =>
      req.session.destroy((error) => {
        
        if (error) {
          console.log(error);
          resolved(false);
          return;
        }
        resolved(true);
        res.clearCookie(__COOKIE__);
      })
    );
  }
}
