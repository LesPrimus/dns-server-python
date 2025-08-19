from app.server import Server
from app.utils import get_args


def main(resolver_host_and_port: str = None):
    server = Server("127.0.0.1", 2053, resolver=resolver_host_and_port)
    server.run()


if __name__ == "__main__":
    args = get_args()
    resolver = args.resolver
    main(resolver)
