---
title: "Simple Geospatial Query in Postgresql without Postgis"
date: 2022-11-12T09:00:00+03:00
draft: false
tags: [spring, spring-boot, spring-jpa, spring-data, postgresql, postgis, geospatial]
description: Let's get started.
---

```java

private static final String HAVERSINE_FORMULA = "(:radiusOfEarth * acos(cos(radians(:latitude)) * cos(radians(s.latitude)) * cos(radians(s.longitude) - radians(:longitude)) + sin(radians(:latitude)) * sin(radians(s.latitude))))";
```

```java
private static final String SEARCH_QUERY = "SELECT s FROM ProfileEntity s WHERE s.gender IN :genderPreferences AND s.birthDate BETWEEN :startDate AND :endDate AND " + HAVERSINE_FORMULA + " < :distance ORDER BY s.lastModifiedDate DESC";
```

```java
@Repository
public interface ProfileRepository extends JpaRepository<ProfileEntity, String> {

  @Query(SEARCH_QUERY)
  Page<ProfileEntity> findProfileEntitiesWithInDistance(
      @Param("radiusOfEarth") double radiusOfEarth,
      @Param("genderPreferences") Set<Gender> genderPreferences,
      @Param("startDate") Date startDate,
      @Param("endDate") Date endDate,
      @Param("latitude") double latitude,
      @Param("longitude") double longitude,
      @Param("distance") double distance,
      Pageable pageable);
}
```
