import zipfile
from pprint import pprint

import click

from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.services.restore import RestoreService


@click.group()
def cli():
    """ cli """
    pass


@cli.group()
def restore():
    """ restore options """
    pass


@restore.command('upgrade', cls=Command)
@click.argument('ipsw', type=click.File('rb'))
def restore_upgrade(lockdown, ipsw):
    RestoreService(lockdown, ipsw)
    ipsw = zipfile.ZipFile(ipsw)
    pprint(ipsw.filelist)

    ipsw.read('BuildManifest.plist')

