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

  const parseJwt = (token: string) => {
    const rawJwtPayload = jwt.verify(token, jwtSecret)
    return normalizeJwtPayload(rawJwtPayload)
  }

  const getPasswordHash = (password: string) => {
    return crypto.createHash('sha256').update(`${passwordSalt}${password}`).digest('hex')
  }

  const applyAuthToExpressApp = ({ expressApp, ctx }: { expressApp: TExpress; ctx: TAppContext }): void => {
    expressApp.use((req: any, res: any, next: any) => {
      const token = req.headers?.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.slice(7)
        : req.cookies[tokenCookieName]
      const jwtPayload = token ? parseJwt(token) : normalizeJwtPayload(undefined)
      void (async () => {
        try {
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
