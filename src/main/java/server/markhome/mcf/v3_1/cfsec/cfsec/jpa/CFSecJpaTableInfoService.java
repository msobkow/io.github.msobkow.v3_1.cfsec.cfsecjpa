// Description: Java 25 Spring JPA Service for TableInfo

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
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	Service for the CFSecTableInfo entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecTableInfoRepository to access them.
 */
@Service("cfsec31JpaTableInfoService")
public class CFSecJpaTableInfoService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaTableInfoRepository cfsec31TableInfoRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaTableInfo, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo create(CFSecJpaTableInfo data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		int originalRequiredTableInfoId = data.getRequiredTableInfoId();
		boolean generatedRequiredTableInfoId = false;
		if(data.getRequiredSchemaName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredSchemaName");
		}
		if(data.getRequiredTableName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredTableName");
		}
		if( data.getRequiredBackingClassCode() < ICFSecTableInfo.BACKINGCLASSCODE_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				S_ProcName,
				0,
				"getRequiredBackingClassCode()",
				data.getRequiredBackingClassCode(),
				ICFSecTableInfo.BACKINGCLASSCODE_MIN_VALUE );
		}
		if( data.getRequiredRuntimeClassCode() < ICFSecTableInfo.RUNTIMECLASSCODE_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				S_ProcName,
				0,
				"getRequiredRuntimeClassCode()",
				data.getRequiredRuntimeClassCode(),
				ICFSecTableInfo.RUNTIMECLASSCODE_MIN_VALUE );
		}
		if(data.getRequiredSecScopeName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredSecScopeName");
		}
		if(data.getRequiredCodeVis() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredCodeVis");
		}
		try {
			if(data.getPKey() != null && cfsec31TableInfoRepository.existsById((Integer)data.getPKey())) {
				return( (CFSecJpaTableInfo)(cfsec31TableInfoRepository.findById((Integer)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			return cfsec31TableInfoRepository.save(data);
		}
		catch(Exception ex) {
				if(generatedRequiredTableInfoId) {
					data.setRequiredTableInfoId(originalRequiredTableInfoId);
				}
			throw new CFLibDbException(getClass(),
				S_ProcName,
				ex);
		}
	}

	/**
	 *	Update an existing entity.
	 *
	 *		@param	data	The entity to be updated.
	 *
	 *		@return The updated entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo update(CFSecJpaTableInfo data) {
		final String S_ProcName = "update";
		if (data == null) {
			return( null );
		}
		if (data.getPKey() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.getPKey()");
		}
		if(data.getRequiredSchemaName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredSchemaName");
		}
		if(data.getRequiredTableName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredTableName");
		}
		if( data.getRequiredBackingClassCode() < ICFSecTableInfo.BACKINGCLASSCODE_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				S_ProcName,
				0,
				"getRequiredBackingClassCode()",
				data.getRequiredBackingClassCode(),
				ICFSecTableInfo.BACKINGCLASSCODE_MIN_VALUE );
		}
		if( data.getRequiredRuntimeClassCode() < ICFSecTableInfo.RUNTIMECLASSCODE_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				S_ProcName,
				0,
				"getRequiredRuntimeClassCode()",
				data.getRequiredRuntimeClassCode(),
				ICFSecTableInfo.RUNTIMECLASSCODE_MIN_VALUE );
		}
		if(data.getRequiredSecScopeName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredSecScopeName");
		}
		if(data.getRequiredCodeVis() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredCodeVis");
		}
		// Ensure the entity exists and that the revision matches
		CFSecJpaTableInfo existing = cfsec31TableInfoRepository.findById((Integer)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecTableInfo to existing object
		// Apply data columns of CFSecTableInfo to existing object
		existing.setRequiredSchemaName(data.getRequiredSchemaName());
		existing.setRequiredTableName(data.getRequiredTableName());
		existing.setRequiredBackingClassCode(data.getRequiredBackingClassCode());
		existing.setRequiredRuntimeClassCode(data.getRequiredRuntimeClassCode());
		existing.setRequiredHasHistory(data.getRequiredHasHistory());
		existing.setRequiredIsMutable(data.getRequiredIsMutable());
		existing.setRequiredSecScopeName(data.getRequiredSecScopeName());
		existing.setRequiredCodeVis(data.getRequiredCodeVis());
		// Save the changes we've made
		return cfsec31TableInfoRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredTableInfoId
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo find(@Param("tableInfoId") int requiredTableInfoId) {
		return( cfsec31TableInfoRepository.get(requiredTableInfoId));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaTableInfo> findAll() {
		return( cfsec31TableInfoRepository.findAll() );
	}

	// CFSecTableInfo specified index finders

	/**
	 *	Find an entity using the columns of the ICFSecTableInfoByTableNameIdxKey as arguments.
	 *
	 *		@param requiredTableName
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo findByTableNameIdx(@Param("tableName") String requiredTableName) {
		return( cfsec31TableInfoRepository.findByTableNameIdx(requiredTableName));
	}

	/**
	 *	ICFSecTableInfoByTableNameIdxKey entity finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoByTableNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo findByTableNameIdx(ICFSecTableInfoByTableNameIdxKey key) {
		return( cfsec31TableInfoRepository.findByTableNameIdx(key.getRequiredTableName()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecTableInfoBySchemaNameIdxKey as arguments.
	 *
	 *		@param requiredSchemaName
	 *
	 *		@return List&lt;CFSecJpaTableInfo&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaTableInfo> findBySchemaNameIdx(@Param("schemaName") String requiredSchemaName) {
		return( cfsec31TableInfoRepository.findBySchemaNameIdx(requiredSchemaName));
	}

	/**
	 *	ICFSecTableInfoBySchemaNameIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoBySchemaNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaTableInfo> findBySchemaNameIdx(ICFSecTableInfoBySchemaNameIdxKey key) {
		return( cfsec31TableInfoRepository.findBySchemaNameIdx(key.getRequiredSchemaName()));
	}

	/**
	 *	Find an entity using the columns of the ICFSecTableInfoBySchemaBkCodeIdxKey as arguments.
	 *
	 *		@param requiredSchemaName
	 *		@param requiredBackingClassCode
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo findBySchemaBkCodeIdx(@Param("schemaName") String requiredSchemaName,
		@Param("backingClassCode") int requiredBackingClassCode) {
		return( cfsec31TableInfoRepository.findBySchemaBkCodeIdx(requiredSchemaName,
			requiredBackingClassCode));
	}

	/**
	 *	ICFSecTableInfoBySchemaBkCodeIdxKey entity finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoBySchemaBkCodeIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo findBySchemaBkCodeIdx(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		return( cfsec31TableInfoRepository.findBySchemaBkCodeIdx(key.getRequiredSchemaName(), key.getRequiredBackingClassCode()));
	}

	/**
	 *	Find an entity using the columns of the ICFSecTableInfoBySchemaRTCodeIdxKey as arguments.
	 *
	 *		@param requiredRuntimeClassCode
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo findBySchemaRTCodeIdx(@Param("runtimeClassCode") int requiredRuntimeClassCode) {
		return( cfsec31TableInfoRepository.findBySchemaRTCodeIdx(requiredRuntimeClassCode));
	}

	/**
	 *	ICFSecTableInfoBySchemaRTCodeIdxKey entity finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoBySchemaRTCodeIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo findBySchemaRTCodeIdx(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		return( cfsec31TableInfoRepository.findBySchemaRTCodeIdx(key.getRequiredRuntimeClassCode()));
	}

	// CFSecTableInfo specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableInfoId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockByIdIdx(@Param("tableInfoId") int requiredTableInfoId) {
		return( cfsec31TableInfoRepository.lockByIdIdx(requiredTableInfoId));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockByTableNameIdx(@Param("tableName") String requiredTableName) {
		return( cfsec31TableInfoRepository.lockByTableNameIdx(requiredTableName));
	}

	/**
	 *	ICFSecTableInfoByTableNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockByTableNameIdx(ICFSecTableInfoByTableNameIdxKey key) {
		return( cfsec31TableInfoRepository.lockByTableNameIdx(key.getRequiredTableName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaTableInfo> lockBySchemaNameIdx(@Param("schemaName") String requiredSchemaName) {
		return( cfsec31TableInfoRepository.lockBySchemaNameIdx(requiredSchemaName));
	}

	/**
	 *	ICFSecTableInfoBySchemaNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaTableInfo> lockBySchemaNameIdx(ICFSecTableInfoBySchemaNameIdxKey key) {
		return( cfsec31TableInfoRepository.lockBySchemaNameIdx(key.getRequiredSchemaName()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 *		@param requiredBackingClassCode
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockBySchemaBkCodeIdx(@Param("schemaName") String requiredSchemaName,
		@Param("backingClassCode") int requiredBackingClassCode) {
		return( cfsec31TableInfoRepository.lockBySchemaBkCodeIdx(requiredSchemaName,
			requiredBackingClassCode));
	}

	/**
	 *	ICFSecTableInfoBySchemaBkCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockBySchemaBkCodeIdx(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		return( cfsec31TableInfoRepository.lockBySchemaBkCodeIdx(key.getRequiredSchemaName(), key.getRequiredBackingClassCode()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredRuntimeClassCode
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockBySchemaRTCodeIdx(@Param("runtimeClassCode") int requiredRuntimeClassCode) {
		return( cfsec31TableInfoRepository.lockBySchemaRTCodeIdx(requiredRuntimeClassCode));
	}

	/**
	 *	ICFSecTableInfoBySchemaRTCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaTableInfo lockBySchemaRTCodeIdx(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		return( cfsec31TableInfoRepository.lockBySchemaRTCodeIdx(key.getRequiredRuntimeClassCode()));
	}

	// CFSecTableInfo specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableInfoId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("tableInfoId") int requiredTableInfoId) {
		cfsec31TableInfoRepository.deleteByIdIdx(requiredTableInfoId);
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByTableNameIdx(@Param("tableName") String requiredTableName) {
		cfsec31TableInfoRepository.deleteByTableNameIdx(requiredTableName);
	}

	/**
	 *	ICFSecTableInfoByTableNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoByTableNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByTableNameIdx(ICFSecTableInfoByTableNameIdxKey key) {
		cfsec31TableInfoRepository.deleteByTableNameIdx(key.getRequiredTableName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySchemaNameIdx(@Param("schemaName") String requiredSchemaName) {
		cfsec31TableInfoRepository.deleteBySchemaNameIdx(requiredSchemaName);
	}

	/**
	 *	ICFSecTableInfoBySchemaNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoBySchemaNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySchemaNameIdx(ICFSecTableInfoBySchemaNameIdxKey key) {
		cfsec31TableInfoRepository.deleteBySchemaNameIdx(key.getRequiredSchemaName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 *		@param requiredBackingClassCode
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySchemaBkCodeIdx(@Param("schemaName") String requiredSchemaName,
		@Param("backingClassCode") int requiredBackingClassCode) {
		cfsec31TableInfoRepository.deleteBySchemaBkCodeIdx(requiredSchemaName,
			requiredBackingClassCode);
	}

	/**
	 *	ICFSecTableInfoBySchemaBkCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoBySchemaBkCodeIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySchemaBkCodeIdx(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		cfsec31TableInfoRepository.deleteBySchemaBkCodeIdx(key.getRequiredSchemaName(), key.getRequiredBackingClassCode());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredRuntimeClassCode
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySchemaRTCodeIdx(@Param("runtimeClassCode") int requiredRuntimeClassCode) {
		cfsec31TableInfoRepository.deleteBySchemaRTCodeIdx(requiredRuntimeClassCode);
	}

	/**
	 *	ICFSecTableInfoBySchemaRTCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecTableInfoBySchemaRTCodeIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteBySchemaRTCodeIdx(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		cfsec31TableInfoRepository.deleteBySchemaRTCodeIdx(key.getRequiredRuntimeClassCode());
	}

}
