// Description: Java 25 Spring JPA Service for SecRoleEnables

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
 *	Service for the CFSecSecRoleEnables entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecRoleEnablesRepository to access them.
 */
@Service("cfsec31JpaSecRoleEnablesService")
public class CFSecJpaSecRoleEnablesService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecRoleEnablesRepository cfsec31SecRoleEnablesRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecRoleEnables, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecRoleEnables create(CFSecJpaSecRoleEnables data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		try {
			if(data.getPKey() != null && cfsec31SecRoleEnablesRepository.existsById((CFSecJpaSecRoleEnablesPKey)data.getPKey())) {
				return( (CFSecJpaSecRoleEnables)(cfsec31SecRoleEnablesRepository.findById((CFSecJpaSecRoleEnablesPKey)(data.getPKey())).get()));
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecRoleEnablesRepository.save(data);
		}
		catch(Exception ex) {
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
	public CFSecJpaSecRoleEnables update(CFSecJpaSecRoleEnables data) {
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
		// Ensure the entity exists and that the revision matches
		CFSecJpaSecRoleEnables existing = cfsec31SecRoleEnablesRepository.findById((CFSecJpaSecRoleEnablesPKey)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecRoleEnables to existing object
		// Apply data columns of CFSecSecRoleEnables to existing object
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecRoleEnablesRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecRoleEnables find(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("enableName") String requiredEnableName) {
		return( cfsec31SecRoleEnablesRepository.get(requiredSecRoleId,
			requiredEnableName));
	}

	/**
	 *	ICFSecSecRoleEnablesPKey based find method for object-based access.
	 *
	 *		@param key The key of the entity to be find.
	 *
	 *		@return The entity find, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecRoleEnables find(ICFSecSecRoleEnablesPKey key) {
		return( cfsec31SecRoleEnablesRepository.get(key.getRequiredSecRoleId(), key.getRequiredEnableName()));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> findAll() {
		return( cfsec31SecRoleEnablesRepository.findAll() );
	}

	// CFSecSecRoleEnables specified index finders

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecRoleEnablesByRoleIdxKey as arguments.
	 *
	 *		@param requiredSecRoleId
	 *
	 *		@return List&lt;CFSecJpaSecRoleEnables&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> findByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId) {
		return( cfsec31SecRoleEnablesRepository.findByRoleIdx(requiredSecRoleId));
	}

	/**
	 *	ICFSecSecRoleEnablesByRoleIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecRoleEnablesByRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> findByRoleIdx(ICFSecSecRoleEnablesByRoleIdxKey key) {
		return( cfsec31SecRoleEnablesRepository.findByRoleIdx(key.getRequiredSecRoleId()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecRoleEnablesByNameIdxKey as arguments.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return List&lt;CFSecJpaSecRoleEnables&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> findByNameIdx(@Param("enableName") String requiredEnableName) {
		return( cfsec31SecRoleEnablesRepository.findByNameIdx(requiredEnableName));
	}

	/**
	 *	ICFSecSecRoleEnablesByNameIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecRoleEnablesByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> findByNameIdx(ICFSecSecRoleEnablesByNameIdxKey key) {
		return( cfsec31SecRoleEnablesRepository.findByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecSecRoleEnables specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecRoleEnables lockByIdIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("enableName") String requiredEnableName) {
		return( cfsec31SecRoleEnablesRepository.lockByIdIdx(requiredSecRoleId,
			requiredEnableName));
	}

	/**
	 *	ICFSecSecRoleEnablesPKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecRoleEnables lockByIdIdx(ICFSecSecRoleEnablesPKey key) {
		return( cfsec31SecRoleEnablesRepository.lockByIdIdx(key.getRequiredSecRoleId(), key.getRequiredEnableName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> lockByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId) {
		return( cfsec31SecRoleEnablesRepository.lockByRoleIdx(requiredSecRoleId));
	}

	/**
	 *	ICFSecSecRoleEnablesByRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> lockByRoleIdx(ICFSecSecRoleEnablesByRoleIdxKey key) {
		return( cfsec31SecRoleEnablesRepository.lockByRoleIdx(key.getRequiredSecRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> lockByNameIdx(@Param("enableName") String requiredEnableName) {
		return( cfsec31SecRoleEnablesRepository.lockByNameIdx(requiredEnableName));
	}

	/**
	 *	ICFSecSecRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecRoleEnables> lockByNameIdx(ICFSecSecRoleEnablesByNameIdxKey key) {
		return( cfsec31SecRoleEnablesRepository.lockByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecSecRoleEnables specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredEnableName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("enableName") String requiredEnableName) {
		cfsec31SecRoleEnablesRepository.deleteByIdIdx(requiredSecRoleId,
			requiredEnableName);
	}

	/**
	 *	ICFSecSecRoleEnablesByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecRoleEnablesByIdIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(ICFSecSecRoleEnablesPKey key) {
		cfsec31SecRoleEnablesRepository.deleteByIdIdx(key.getRequiredSecRoleId(), key.getRequiredEnableName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId) {
		cfsec31SecRoleEnablesRepository.deleteByRoleIdx(requiredSecRoleId);
	}

	/**
	 *	ICFSecSecRoleEnablesByRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecRoleEnablesByRoleIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByRoleIdx(ICFSecSecRoleEnablesByRoleIdxKey key) {
		cfsec31SecRoleEnablesRepository.deleteByRoleIdx(key.getRequiredSecRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(@Param("enableName") String requiredEnableName) {
		cfsec31SecRoleEnablesRepository.deleteByNameIdx(requiredEnableName);
	}

	/**
	 *	ICFSecSecRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecRoleEnablesByNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(ICFSecSecRoleEnablesByNameIdxKey key) {
		cfsec31SecRoleEnablesRepository.deleteByNameIdx(key.getRequiredEnableName());
	}

}
