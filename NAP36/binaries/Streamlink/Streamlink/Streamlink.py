import sys, os
path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'Dependencies'))
path2 = os.path.abspath(os.path.join(os.path.dirname(__file__)))
if not path in sys.path:
    sys.path.insert(0, path)
if not path2 in sys.path:
    sys.path.insert(0, path2)
if __name__ == '__main__':
    from streamlink_cli.main import main
    main()