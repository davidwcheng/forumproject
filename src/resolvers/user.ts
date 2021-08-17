import { MyContext } from "src/types";
import {
  Arg,
  Ctx,
  Field,
  InputType,
  Mutation,
  ObjectType,
  Resolver,
} from "type-graphql";
import { User } from "../entities/User";
import argon2 from "argon2";

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
@Resolver()
export class UserResolver {
  @Mutation(() => User)
  async register(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    if(options.username.length <= 2){
      return {
        errors: [{
          field: 'username',
          message: 'username is too short, length of 3 or more'
        }]
      }
    }

    if(options.password.length <= 3){
      return {
        errors: [{
          field: 'password',
          message: 'password is too short, length of 4 or more'
        }]
      }
    }
   
    const hashedPassword = await argon2.hash(options.password);
    const user = em.create(User, {
      username: options.username,
      password: hashedPassword,
    });

    await em.persistAndFlush(user);
    return {user};
  }

  @Mutation(() => UserResponse)
  async login(
    @Arg("options") options: UsernamePasswordInput,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(User, { username: options.username });
    if (!user) {
      return {
        errors: [{
            field: "username",
            message: "invalid login, try again"
          }],
      };
    }
    const valid = await argon2.verify(user.password, options.password);
    if(!valid){
        return{
            errors: [{
                field:"password",
                message:"invalid login, try again"
            }]
        };
    }
    
    return {user};
  }
}
