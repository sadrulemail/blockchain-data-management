"""S3 backend against an in-memory S3 (moto): same contract as the filesystem store."""

import boto3
import pytest
from moto import mock_aws

from dataledger.config import Settings
from dataledger.platform import make_store
from dataledger.storage import LocalObjectStore, ObjectNotFound, S3ObjectStore, StorageIntegrityError


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="eu-west-1")
        client.create_bucket(Bucket="ledger", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
        yield client


def test_put_get_delete_round_trip(s3):
    store = S3ObjectStore("ledger", "objects/", client=s3)
    object_id = store.put(b"sealed bytes")
    assert store.put(b"sealed bytes") == object_id  # idempotent, content addressed
    key = f"objects/{object_id[:2]}/{object_id[2:4]}/{object_id}"
    assert s3.head_object(Bucket="ledger", Key=key)["ContentLength"] == 12
    assert store.exists(object_id)
    assert store.get(object_id) == b"sealed bytes"
    assert store.delete(object_id)
    assert not store.delete(object_id)
    assert not store.exists(object_id)
    with pytest.raises(ObjectNotFound):
        store.get(object_id)


def test_changed_object_fails_its_hash_check(s3):
    store = S3ObjectStore("ledger", client=s3)
    object_id = store.put(b"original")
    s3.put_object(Bucket="ledger", Key=store._key(object_id), Body=b"tampered")
    with pytest.raises(StorageIntegrityError):
        store.get(object_id)


def test_rejects_malformed_ids(s3):
    store = S3ObjectStore("ledger", client=s3)
    with pytest.raises(ValueError, match="malformed"):
        store.exists("../../etc/passwd")


def test_other_errors_are_not_swallowed(s3):
    store = S3ObjectStore("missing-bucket", client=s3)
    with pytest.raises(Exception, match=r"NoSuchBucket|Not Found|404") as info:
        store.put(b"x")
    assert not isinstance(info.value, ObjectNotFound)


def test_store_is_chosen_from_settings(tmp_path, s3):
    local = make_store(Settings(object_store_dir=tmp_path, _env_file=None))
    assert isinstance(local, LocalObjectStore)
    with pytest.raises(ValueError, match="S3_BUCKET"):
        make_store(Settings(object_store="s3", _env_file=None))
    remote = make_store(Settings(object_store="s3", s3_bucket="ledger", s3_region="eu-west-1", _env_file=None))
    assert isinstance(remote, S3ObjectStore)
    assert remote.prefix == "objects"
