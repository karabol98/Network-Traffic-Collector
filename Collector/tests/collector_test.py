import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from query import MetaQuery

def test_simple_index_without_alias():
    query = "SELECT * FROM index1 WHERE timestamp > '2023-01-01'"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    assert len(result) == 1
    assert result[0]['index'] == 'index1'
    assert result[0]['alias'] is None
    assert result[0]['complete_string'] == 'index1'

def test_index_with_as_keyword_alias():
    query = "SELECT * FROM index1 AS i1 WHERE timestamp > '2023-01-01'"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 1
    assert result[0] == 'index1'


def test_index_with_implicit_alias():
    query = "SELECT * FROM index1 i1 WHERE timestamp > '2023-01-01'"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    assert len(result) == 1
    assert result[0] == 'index1'


def test_multiple_indices_with_aliases():
    query = "SELECT * FROM index1 i1 JOIN index2 AS i2 ON i1.id = i2.id"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 2
    assert result[0] == 'index1'
    assert result[1] == 'index2'

def test_sql_keywords_not_treated_as_aliases():
    query = "SELECT * FROM index1 WHERE timestamp > '2023-01-01' GROUP BY date"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 1
    assert result[0]== 'index1'

def test_no_matching_indices():
    query = "SELECT * FROM unknown_index WHERE timestamp > '2023-01-01'"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 0

def test_case_insensitivity():
    query = "SELECT * FROM INDEX1 I1"
    available_indices = ["index1", "index2", "index3"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    assert len(result) == 1
    assert result[0]== 'INDEX1'

def test_subquery_with_indices():
    query = """
    SELECT * FROM
      (SELECT * FROM index1 WHERE value > 10) AS subq
    JOIN index2 ON subq.id = index2.id
    """
    available_indices = ["index1", "index2"]

    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 2
    assert 'index1' in result
    assert 'index2' in result

def test_joins_parquet():
    query = """
        SELECT *
    FROM read_parquet('file1.parquet') AS t1
    JOIN read_parquet('file2.parquet') AS t2
    ON t1.common_column = t2.common_column;
    """

    available_indices = ["file1", "file2"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 0

def test_case_internals():
    query = """ SELECT *FROM _schema; """

    available_indices = []
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 0


def test_read_parquet():
    query = """
        SELECT   _index, Sum(_cnt)
        FROM     (
                    SELECT   _index,
                            Count(*) AS _cnt
                    FROM     (
                                    SELECT *
                                    FROM   Read_parquet(['./data/_internal/buckets/20250305111507-20250306001224_packed_20250306003227.parquet','./data/_internal/buckets/20250307163417-20250307173417_0.parquet'], union_by_name = true)
                                    WHERE  _time >= '2024-12-07 18:30:45.686000'
                                    AND    _time <= '2025-03-07 18:30:45.686000'
                                    UNION ALL
                                    SELECT *
                                    FROM   bucket_20250307175715_20250307185715_0
                                    WHERE  Cast(_time AS TIMESTAMP) >= timestamp '2024-12-07 18:30:45.686000'
                                    AND    cast(_time AS timestamp) <= timestamp '2025-03-07 18:30:45.686000') AS _internal
                    GROUP BY _index
                    UNION ALL
                    SELECT   _index,
                            count(*) AS _cnt
                    FROM     (
                                    SELECT *
                                    FROM   read_parquet(['./data/pdmfc_fortigate/buckets/20250304000430-20250305001731_packed_20250305060023.parquet'], union_by_name = true)
                                    WHERE  _time >= '2024-12-07 18:30:45.686000'
                                    AND    _time <= '2025-03-07 18:30:45.686000') AS pdmfc_fortigate
                    GROUP BY _index) t
        GROUP BY _index
    """

    available_indices = ["pdmfc_fortigate","_internal"]
    metaquery = MetaQuery(query, available_indices)
    result = metaquery.matching_tables

    print(result)
    assert len(result) == 0

def test_simple_index_without_alias():
    query = "SELECT * FROM index* WHERE timestamp > '2023-01-01'"
    available_indices = ["index1", "index2", "index3"]

    metaquery = MetaQuery(query, available_indices)
    indices = metaquery.matching_tables

    assert len(indices) == 3
    assert 'index1' in indices
    assert 'index2' in indices
    assert 'index3' in indices

def test_count_star_from_star_group_by():
    query = "select count(*) from * group by _index"
    available_indices = ["index1", "index2", "index3"]

    metaquery = MetaQuery(query, available_indices)
    indices = metaquery.matching_tables

    # This query should match all available indices
    assert len(indices) == 3
    assert 'index1' in indices
    assert 'index2' in indices
    assert 'index3' in indices

def test_max_time():
    query = "select max(_time) from *"
    available_indices = ["forti", "_internal", "pdmfc_linux_syslog"]

    metaquery = MetaQuery(query, available_indices)
    indices = metaquery.matching_tables

    # This query should match all available indices
    assert len(indices) == 3
    assert 'forti' in indices
    assert '_internal' in indices
    assert 'pdmfc_linux_syslog' in indices

