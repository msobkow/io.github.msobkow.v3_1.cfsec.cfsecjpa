// Description: Java 25 Spring JPA Repository for SecSysRoleEnables

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	JpaRepository for the CFSecJpaSecSysRoleEnables entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecSysRoleEnablesRepository extends JpaRepository<CFSecJpaSecSysRoleEnables, CFSecJpaSecSysRoleEnablesPKey> {

	@Transactional
	@Modifying
	CFSecJpaSecSysRoleEnables save(CFSecJpaSecSysRoleEnables obj);

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecSysRoleEnables r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId and r.requiredParentEnableGroup.requiredName = :enableName")
	CFSecJpaSecSysRoleEnables get(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId,
		@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecSysRoleEnablesPKey based read method for object-based access.
	 *
	 *		@param key The key of the entity to be read.
	 *
	 *		@return The entity read, usually from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecSysRoleEnables get(ICFSecSecSysRoleEnablesPKey key) {
		return( get(key.getRequiredSecSysRoleId(), key.getRequiredEnableName()));
	}

	// CFSecJpaSecSysRoleEnables specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecSysRoleEnablesBySysRoleIdxKey as arguments.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleEnables&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecSysRoleEnables r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId")
	List<CFSecJpaSecSysRoleEnables> findBySysRoleIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId);

	/**
	 *	CFSecSecSysRoleEnablesBySysRoleIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleEnablesBySysRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecSysRoleEnables> findBySysRoleIdx(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		return( findBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecSysRoleEnablesByNameIdxKey as arguments.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return List&lt;CFSecJpaSecSysRoleEnables&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecSysRoleEnables r where r.requiredParentEnableGroup.requiredName = :enableName")
	List<CFSecJpaSecSysRoleEnables> findByNameIdx(@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecSysRoleEnablesByNameIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleEnablesByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecSysRoleEnables> findByNameIdx(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		return( findByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecJpaSecSysRoleEnables specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRoleEnables r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId and r.requiredParentEnableGroup.requiredName = :enableName")
	CFSecJpaSecSysRoleEnables lockByIdIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId,
		@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecSysRoleEnablesByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecSysRoleEnables lockByIdIdx(ICFSecSecSysRoleEnablesPKey key) {
		return( lockByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredEnableName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRoleEnables r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId")
	List<CFSecJpaSecSysRoleEnables> lockBySysRoleIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId);

	/**
	 *	CFSecSecSysRoleEnablesBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecSysRoleEnables> lockBySysRoleIdx(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		return( lockBySysRoleIdx(key.getRequiredSecSysRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRoleEnables r where r.requiredParentEnableGroup.requiredName = :enableName")
	List<CFSecJpaSecSysRoleEnables> lockByNameIdx(@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecSysRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecSysRoleEnables> lockByNameIdx(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		return( lockByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecJpaSecSysRoleEnables specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *		@param requiredEnableName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRoleEnables r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId and r.requiredParentEnableGroup.requiredName = :enableName")
	void deleteByIdIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId,
		@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecSysRoleEnablesByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleEnablesByIdIdxKey of the entity to be locked.
	 */
	default void deleteByIdIdx(ICFSecSecSysRoleEnablesPKey key) {
		deleteByIdIdx(key.getRequiredSecSysRoleId(), key.getRequiredEnableName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRoleEnables r where r.requiredContainerSysRole.requiredSecSysRoleId = :secSysRoleId")
	void deleteBySysRoleIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId);

	/**
	 *	CFSecSecSysRoleEnablesBySysRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleEnablesBySysRoleIdxKey of the entity to be locked.
	 */
	default void deleteBySysRoleIdx(ICFSecSecSysRoleEnablesBySysRoleIdxKey key) {
		deleteBySysRoleIdx(key.getRequiredSecSysRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRoleEnables r where r.requiredParentEnableGroup.requiredName = :enableName")
	void deleteByNameIdx(@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecSysRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleEnablesByNameIdxKey of the entity to be locked.
	 */
	default void deleteByNameIdx(ICFSecSecSysRoleEnablesByNameIdxKey key) {
		deleteByNameIdx(key.getRequiredEnableName());
	}

}
