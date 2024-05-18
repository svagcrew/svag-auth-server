import crypto from 'crypto'
import type { Express } from 'express'
import jwt from 'jsonwebtoken'
import { Passport } from 'passport'
import { ExtractJwt, Strategy as JWTStrategy } from 'passport-jwt'

export const createAuthThings = <TAppContext, TJwtPayload extends object | string, TMe>({
  jwtSecret,
  passwordSalt,
  normalizeJwtPayload,
  getMeFromJwtPayload,
  tokenCookieName,
}: {
  jwtSecret: string
  passwordSalt: string
  normalizeJwtPayload: (jwtPayload: any) => TJwtPayload
  getMeFromJwtPayload: (jwtPayload: TJwtPayload, ctx: TAppContext) => TMe
  tokenCookieName: string
}) => {
  const signJwt = (jwtPayload: any) => {
    const normalizedPayload = normalizeJwtPayload(jwtPayload)
    return jwt.sign(normalizedPayload, jwtSecret)
  }

  const getPasswordHash = (password: string) => {
    return crypto.createHash('sha256').update(`${passwordSalt}${password}`).digest('hex')
  }

  const applyAuthToExpressApp = ({ expressApp, ctx }: { expressApp: Express; ctx: TAppContext }): void => {
    const passport = new Passport()

    passport.use(
      new JWTStrategy(
        {
          secretOrKey: jwtSecret,
          jwtFromRequest: (req) => {
            if (req.headers.authorization?.startsWith('Bearer ')) {
              return ExtractJwt.fromAuthHeaderWithScheme('Bearer')(req)
            } else if (req.cookies[tokenCookieName]) {
              return req.cookies[tokenCookieName]
            }
            return null
          },
        },
        (jwtPayload: any, done) => {
          ;(async () => {
            try {
              done(null, await getMeFromJwtPayload(normalizeJwtPayload(jwtPayload), ctx))
            } catch (error) {
              done(error, false)
            }
          })()
        }
      )
    )

    expressApp.use((req: any, res: any, next: any) => {
      passport.authenticate('jwt', { session: false }, (...args: any[]) => {
        ;(req as any).me = args[1] || undefined
        next()
      })(req, res, next)
    })
  }

  return {
    applyAuthToExpressApp,
    signJwt: signJwt as (jwtPayload: TJwtPayload) => string,
    getPasswordHash,
    getMeFromJwtPayload,
  }
}
