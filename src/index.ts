import crypto from 'crypto'
import type { Express } from 'express'
import jwt from 'jsonwebtoken'

type LikeRequest = Record<string, any>

export const createAuthThings = <
  TAppContext,
  TJwtPayload extends object | string,
  TMeFromJwtPayload,
  TExpress extends Express = Express,
  TRequest extends LikeRequest = LikeRequest,
>({
  jwtSecret,
  passwordSalt,
  normalizeJwtPayload,
  getMeFromJwtPayload,
  tokenCookieName,
}: {
  jwtSecret: string
  passwordSalt: string
  normalizeJwtPayload: (jwtPayload: any) => TJwtPayload
  getMeFromJwtPayload: (
    jwtPayload: TJwtPayload,
    ctx: TAppContext,
    req?: TRequest
  ) => Promise<TMeFromJwtPayload> | TMeFromJwtPayload
  tokenCookieName: string
}) => {
  const signJwt = (jwtPayload: any) => {
    const normalizedPayload = normalizeJwtPayload(jwtPayload)
    return jwt.sign(normalizedPayload, jwtSecret)
  }

  const parseJwt = async (token: string) => {
    return await new Promise<TJwtPayload>((resolve, reject) => {
      jwt.verify(token, jwtSecret, (error, decoded) => {
        try {
          if (error) {
            resolve(normalizeJwtPayload(undefined))
          } else {
            resolve(normalizeJwtPayload(decoded))
          }
        } catch (error) {
          reject(error)
        }
      })
    })
  }

  const getPasswordHash = (password: string) => {
    return crypto.createHash('sha256').update(`${passwordSalt}${password}`).digest('hex')
  }

  const applyAuthToExpressApp = ({ expressApp, ctx }: { expressApp: TExpress; ctx: TAppContext }): void => {
    expressApp.use((req: any, res: any, next: any) => {
      const token = req.headers?.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.slice(7)
        : req.cookies[tokenCookieName]
      void (async () => {
        try {
          const jwtPayload = token ? await parseJwt(token) : normalizeJwtPayload(undefined)
          const meFromJwtPayload = await getMeFromJwtPayload(jwtPayload, ctx, req)
          ;(req as any).me = meFromJwtPayload
          next()
        } catch (error) {
          next(error)
        }
      })()
    })
  }

  return {
    applyAuthToExpressApp,
    signJwt: signJwt as (jwtPayload: TJwtPayload) => string,
    getPasswordHash,
    getMeFromJwtPayload,
  }
}
