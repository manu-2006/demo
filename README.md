# ZELVON — Restaurant Operating System

**Scan · Order · Pay · Grow**

ZELVON is a premium multi-tenant restaurant operating platform.

Secure multi-tenant QR ordering platform for restaurants in Karnataka.

## V1
- Table-specific QR menus
- Kannada + English menu
- Customer cart and ordering
- Live restaurant/kitchen order flow
- Bill requests
- Tenant-isolated data model
- Role-based restaurant staff access

## Security
All private restaurant data is scoped by authenticated restaurant membership. Customer sessions use opaque random tokens and never expose customer records across tables/restaurants. Secrets stay server-side.

## Architecture
- Web: React + Vite
- API: Node.js + Express
- Database: PostgreSQL
- Auth: HttpOnly session cookies
